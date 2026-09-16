rule TTP_XOR_MULT_DOSStub_f91e {
  strings:
    $key_f91e = { ad 76 [2] d9 6e [2] 9e 6c [2] d9 7d [2] 97 71 [2] 9b 7b [2] 8c 70 [2] 97 3e [2] aa }

  condition:
    any of them
}