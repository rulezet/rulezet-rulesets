rule TTP_XOR_MULT_DOSStub_45b6 {
  strings:
    $key_45b6 = { 11 de [2] 65 c6 [2] 22 c4 [2] 65 d5 [2] 2b d9 [2] 27 d3 [2] 30 d8 [2] 2b 96 [2] 16 }

  condition:
    any of them
}