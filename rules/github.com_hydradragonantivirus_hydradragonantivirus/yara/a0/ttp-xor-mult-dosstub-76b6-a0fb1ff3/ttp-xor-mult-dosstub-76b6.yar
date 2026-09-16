rule TTP_XOR_MULT_DOSStub_76b6 {
  strings:
    $key_76b6 = { 22 de [2] 56 c6 [2] 11 c4 [2] 56 d5 [2] 18 d9 [2] 14 d3 [2] 03 d8 [2] 18 96 [2] 25 }

  condition:
    any of them
}