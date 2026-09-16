rule TTP_XOR_MULT_DOSStub_55b6 {
  strings:
    $key_55b6 = { 01 de [2] 75 c6 [2] 32 c4 [2] 75 d5 [2] 3b d9 [2] 37 d3 [2] 20 d8 [2] 3b 96 [2] 06 }

  condition:
    any of them
}