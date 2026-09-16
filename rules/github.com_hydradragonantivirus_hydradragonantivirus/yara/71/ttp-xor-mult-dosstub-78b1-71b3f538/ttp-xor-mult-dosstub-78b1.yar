rule TTP_XOR_MULT_DOSStub_78b1 {
  strings:
    $key_78b1 = { 2c d9 [2] 58 c1 [2] 1f c3 [2] 58 d2 [2] 16 de [2] 1a d4 [2] 0d df [2] 16 91 [2] 2b }

  condition:
    any of them
}