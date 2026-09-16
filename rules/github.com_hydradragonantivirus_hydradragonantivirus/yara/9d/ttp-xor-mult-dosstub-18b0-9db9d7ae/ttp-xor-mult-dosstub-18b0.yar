rule TTP_XOR_MULT_DOSStub_18b0 {
  strings:
    $key_18b0 = { 4c d8 [2] 38 c0 [2] 7f c2 [2] 38 d3 [2] 76 df [2] 7a d5 [2] 6d de [2] 76 90 [2] 4b }

  condition:
    any of them
}