rule TTP_XOR_MULT_DOSStub_39b6 {
  strings:
    $key_39b6 = { 6d de [2] 19 c6 [2] 5e c4 [2] 19 d5 [2] 57 d9 [2] 5b d3 [2] 4c d8 [2] 57 96 [2] 6a }

  condition:
    any of them
}