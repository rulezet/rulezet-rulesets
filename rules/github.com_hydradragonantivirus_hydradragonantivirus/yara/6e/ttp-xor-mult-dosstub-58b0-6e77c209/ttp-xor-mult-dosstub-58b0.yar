rule TTP_XOR_MULT_DOSStub_58b0 {
  strings:
    $key_58b0 = { 0c d8 [2] 78 c0 [2] 3f c2 [2] 78 d3 [2] 36 df [2] 3a d5 [2] 2d de [2] 36 90 [2] 0b }

  condition:
    any of them
}