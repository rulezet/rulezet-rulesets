rule TTP_XOR_MULT_DOSStub_6cb1 {
  strings:
    $key_6cb1 = { 38 d9 [2] 4c c1 [2] 0b c3 [2] 4c d2 [2] 02 de [2] 0e d4 [2] 19 df [2] 02 91 [2] 3f }

  condition:
    any of them
}