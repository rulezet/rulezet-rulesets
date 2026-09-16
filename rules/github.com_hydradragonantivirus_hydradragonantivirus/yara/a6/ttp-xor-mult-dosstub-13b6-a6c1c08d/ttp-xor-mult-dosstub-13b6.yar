rule TTP_XOR_MULT_DOSStub_13b6 {
  strings:
    $key_13b6 = { 47 de [2] 33 c6 [2] 74 c4 [2] 33 d5 [2] 7d d9 [2] 71 d3 [2] 66 d8 [2] 7d 96 [2] 40 }

  condition:
    any of them
}