rule TTP_XOR_MULT_DOSStub_0fb0 {
  strings:
    $key_0fb0 = { 5b d8 [2] 2f c0 [2] 68 c2 [2] 2f d3 [2] 61 df [2] 6d d5 [2] 7a de [2] 61 90 [2] 5c }

  condition:
    any of them
}