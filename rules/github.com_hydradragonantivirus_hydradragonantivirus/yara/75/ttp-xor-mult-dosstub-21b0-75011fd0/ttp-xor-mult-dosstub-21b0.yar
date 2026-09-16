rule TTP_XOR_MULT_DOSStub_21b0 {
  strings:
    $key_21b0 = { 75 d8 [2] 01 c0 [2] 46 c2 [2] 01 d3 [2] 4f df [2] 43 d5 [2] 54 de [2] 4f 90 [2] 72 }

  condition:
    any of them
}