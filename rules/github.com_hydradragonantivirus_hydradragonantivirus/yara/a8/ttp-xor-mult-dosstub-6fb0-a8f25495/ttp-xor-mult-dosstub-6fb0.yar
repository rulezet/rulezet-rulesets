rule TTP_XOR_MULT_DOSStub_6fb0 {
  strings:
    $key_6fb0 = { 3b d8 [2] 4f c0 [2] 08 c2 [2] 4f d3 [2] 01 df [2] 0d d5 [2] 1a de [2] 01 90 [2] 3c }

  condition:
    any of them
}