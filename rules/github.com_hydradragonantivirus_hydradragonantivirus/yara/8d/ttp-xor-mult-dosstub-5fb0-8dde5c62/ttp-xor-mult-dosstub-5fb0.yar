rule TTP_XOR_MULT_DOSStub_5fb0 {
  strings:
    $key_5fb0 = { 0b d8 [2] 7f c0 [2] 38 c2 [2] 7f d3 [2] 31 df [2] 3d d5 [2] 2a de [2] 31 90 [2] 0c }

  condition:
    any of them
}