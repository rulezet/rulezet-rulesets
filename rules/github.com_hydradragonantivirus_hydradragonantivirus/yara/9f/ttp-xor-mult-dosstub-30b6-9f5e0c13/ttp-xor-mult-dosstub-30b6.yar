rule TTP_XOR_MULT_DOSStub_30b6 {
  strings:
    $key_30b6 = { 64 de [2] 10 c6 [2] 57 c4 [2] 10 d5 [2] 5e d9 [2] 52 d3 [2] 45 d8 [2] 5e 96 [2] 63 }

  condition:
    any of them
}