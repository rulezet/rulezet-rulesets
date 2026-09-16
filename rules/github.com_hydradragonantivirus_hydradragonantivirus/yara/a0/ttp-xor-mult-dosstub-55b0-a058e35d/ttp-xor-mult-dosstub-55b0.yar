rule TTP_XOR_MULT_DOSStub_55b0 {
  strings:
    $key_55b0 = { 01 d8 [2] 75 c0 [2] 32 c2 [2] 75 d3 [2] 3b df [2] 37 d5 [2] 20 de [2] 3b 90 [2] 06 }

  condition:
    any of them
}