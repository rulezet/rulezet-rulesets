rule TTP_XOR_MULT_DOSStub_3fb6 {
  strings:
    $key_3fb6 = { 6b de [2] 1f c6 [2] 58 c4 [2] 1f d5 [2] 51 d9 [2] 5d d3 [2] 4a d8 [2] 51 96 [2] 6c }

  condition:
    any of them
}