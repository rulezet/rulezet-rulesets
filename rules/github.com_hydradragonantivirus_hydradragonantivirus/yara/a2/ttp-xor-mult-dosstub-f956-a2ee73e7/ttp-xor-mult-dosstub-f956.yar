rule TTP_XOR_MULT_DOSStub_f956 {
  strings:
    $key_f956 = { ad 3e [2] d9 26 [2] 9e 24 [2] d9 35 [2] 97 39 [2] 9b 33 [2] 8c 38 [2] 97 76 [2] aa }

  condition:
    any of them
}