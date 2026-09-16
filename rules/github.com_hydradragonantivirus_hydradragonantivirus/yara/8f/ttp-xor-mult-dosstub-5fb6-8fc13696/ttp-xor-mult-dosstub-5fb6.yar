rule TTP_XOR_MULT_DOSStub_5fb6 {
  strings:
    $key_5fb6 = { 0b de [2] 7f c6 [2] 38 c4 [2] 7f d5 [2] 31 d9 [2] 3d d3 [2] 2a d8 [2] 31 96 [2] 0c }

  condition:
    any of them
}