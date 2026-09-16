rule TTP_XOR_MULT_DOSStub_5eb6 {
  strings:
    $key_5eb6 = { 0a de [2] 7e c6 [2] 39 c4 [2] 7e d5 [2] 30 d9 [2] 3c d3 [2] 2b d8 [2] 30 96 [2] 0d }

  condition:
    any of them
}