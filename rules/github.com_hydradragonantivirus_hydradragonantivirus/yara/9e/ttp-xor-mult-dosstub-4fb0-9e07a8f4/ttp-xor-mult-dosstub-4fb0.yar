rule TTP_XOR_MULT_DOSStub_4fb0 {
  strings:
    $key_4fb0 = { 1b d8 [2] 6f c0 [2] 28 c2 [2] 6f d3 [2] 21 df [2] 2d d5 [2] 3a de [2] 21 90 [2] 1c }

  condition:
    any of them
}