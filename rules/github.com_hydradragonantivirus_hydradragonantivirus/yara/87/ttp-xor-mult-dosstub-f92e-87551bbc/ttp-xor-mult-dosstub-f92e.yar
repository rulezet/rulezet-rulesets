rule TTP_XOR_MULT_DOSStub_f92e {
  strings:
    $key_f92e = { ad 46 [2] d9 5e [2] 9e 5c [2] d9 4d [2] 97 41 [2] 9b 4b [2] 8c 40 [2] 97 0e [2] aa }

  condition:
    any of them
}