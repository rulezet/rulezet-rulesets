rule TTP_XOR_MULT_DOSStub_7eb6 {
  strings:
    $key_7eb6 = { 2a de [2] 5e c6 [2] 19 c4 [2] 5e d5 [2] 10 d9 [2] 1c d3 [2] 0b d8 [2] 10 96 [2] 2d }

  condition:
    any of them
}