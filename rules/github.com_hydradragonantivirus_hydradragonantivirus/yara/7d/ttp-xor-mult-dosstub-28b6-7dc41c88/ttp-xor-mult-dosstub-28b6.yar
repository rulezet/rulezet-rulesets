rule TTP_XOR_MULT_DOSStub_28b6 {
  strings:
    $key_28b6 = { 7c de [2] 08 c6 [2] 4f c4 [2] 08 d5 [2] 46 d9 [2] 4a d3 [2] 5d d8 [2] 46 96 [2] 7b }

  condition:
    any of them
}