rule TTP_XOR_MULT_DOSStub_78b0 {
  strings:
    $key_78b0 = { 2c d8 [2] 58 c0 [2] 1f c2 [2] 58 d3 [2] 16 df [2] 1a d5 [2] 0d de [2] 16 90 [2] 2b }

  condition:
    any of them
}