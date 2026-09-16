rule TTP_XOR_MULT_DOSStub_16b6 {
  strings:
    $key_16b6 = { 42 de [2] 36 c6 [2] 71 c4 [2] 36 d5 [2] 78 d9 [2] 74 d3 [2] 63 d8 [2] 78 96 [2] 45 }

  condition:
    any of them
}