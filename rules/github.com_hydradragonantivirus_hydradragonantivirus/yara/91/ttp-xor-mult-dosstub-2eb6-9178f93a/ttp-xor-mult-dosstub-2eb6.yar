rule TTP_XOR_MULT_DOSStub_2eb6 {
  strings:
    $key_2eb6 = { 7a de [2] 0e c6 [2] 49 c4 [2] 0e d5 [2] 40 d9 [2] 4c d3 [2] 5b d8 [2] 40 96 [2] 7d }

  condition:
    any of them
}