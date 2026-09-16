rule TTP_XOR_MULT_DOSStub_21b6 {
  strings:
    $key_21b6 = { 75 de [2] 01 c6 [2] 46 c4 [2] 01 d5 [2] 4f d9 [2] 43 d3 [2] 54 d8 [2] 4f 96 [2] 72 }

  condition:
    any of them
}