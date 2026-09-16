rule TTP_XOR_MULT_DOSStub_f91c {
  strings:
    $key_f91c = { ad 74 [2] d9 6c [2] 9e 6e [2] d9 7f [2] 97 73 [2] 9b 79 [2] 8c 72 [2] 97 3c [2] aa }

  condition:
    any of them
}