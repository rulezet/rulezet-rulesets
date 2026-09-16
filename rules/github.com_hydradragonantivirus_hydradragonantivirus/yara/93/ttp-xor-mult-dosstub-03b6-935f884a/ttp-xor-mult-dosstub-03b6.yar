rule TTP_XOR_MULT_DOSStub_03b6 {
  strings:
    $key_03b6 = { 57 de [2] 23 c6 [2] 64 c4 [2] 23 d5 [2] 6d d9 [2] 61 d3 [2] 76 d8 [2] 6d 96 [2] 50 }

  condition:
    any of them
}