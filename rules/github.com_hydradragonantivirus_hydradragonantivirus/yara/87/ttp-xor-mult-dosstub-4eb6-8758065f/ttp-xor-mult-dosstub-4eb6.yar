rule TTP_XOR_MULT_DOSStub_4eb6 {
  strings:
    $key_4eb6 = { 1a de [2] 6e c6 [2] 29 c4 [2] 6e d5 [2] 20 d9 [2] 2c d3 [2] 3b d8 [2] 20 96 [2] 1d }

  condition:
    any of them
}