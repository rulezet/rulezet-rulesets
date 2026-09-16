rule TTP_XOR_MULT_DOSStub_42b0 {
  strings:
    $key_42b0 = { 16 d8 [2] 62 c0 [2] 25 c2 [2] 62 d3 [2] 2c df [2] 20 d5 [2] 37 de [2] 2c 90 [2] 11 }

  condition:
    any of them
}