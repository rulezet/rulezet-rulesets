rule TTP_XOR_MULT_DOSStub_08b0 {
  strings:
    $key_08b0 = { 5c d8 [2] 28 c0 [2] 6f c2 [2] 28 d3 [2] 66 df [2] 6a d5 [2] 7d de [2] 66 90 [2] 5b }

  condition:
    any of them
}