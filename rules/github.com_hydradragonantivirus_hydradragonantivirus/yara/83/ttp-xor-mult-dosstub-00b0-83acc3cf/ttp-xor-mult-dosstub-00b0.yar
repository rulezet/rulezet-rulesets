rule TTP_XOR_MULT_DOSStub_00b0 {
  strings:
    $key_00b0 = { 54 d8 [2] 20 c0 [2] 67 c2 [2] 20 d3 [2] 6e df [2] 62 d5 [2] 75 de [2] 6e 90 [2] 53 }

  condition:
    any of them
}