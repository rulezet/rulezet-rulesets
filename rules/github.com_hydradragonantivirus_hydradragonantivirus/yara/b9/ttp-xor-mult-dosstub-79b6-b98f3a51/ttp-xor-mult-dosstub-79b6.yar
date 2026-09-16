rule TTP_XOR_MULT_DOSStub_79b6 {
  strings:
    $key_79b6 = { 2d de [2] 59 c6 [2] 1e c4 [2] 59 d5 [2] 17 d9 [2] 1b d3 [2] 0c d8 [2] 17 96 [2] 2a }

  condition:
    any of them
}