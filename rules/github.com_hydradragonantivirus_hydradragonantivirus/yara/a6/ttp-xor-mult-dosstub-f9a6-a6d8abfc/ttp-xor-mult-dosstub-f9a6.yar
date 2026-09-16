rule TTP_XOR_MULT_DOSStub_f9a6 {
  strings:
    $key_f9a6 = { ad ce [2] d9 d6 [2] 9e d4 [2] d9 c5 [2] 97 c9 [2] 9b c3 [2] 8c c8 [2] 97 86 [2] aa }

  condition:
    any of them
}