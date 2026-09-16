rule TTP_XOR_MULT_DOSStub_25b6 {
  strings:
    $key_25b6 = { 71 de [2] 05 c6 [2] 42 c4 [2] 05 d5 [2] 4b d9 [2] 47 d3 [2] 50 d8 [2] 4b 96 [2] 76 }

  condition:
    any of them
}