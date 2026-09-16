rule TTP_XOR_MULT_DOSStub_71b6 {
  strings:
    $key_71b6 = { 25 de [2] 51 c6 [2] 16 c4 [2] 51 d5 [2] 1f d9 [2] 13 d3 [2] 04 d8 [2] 1f 96 [2] 22 }

  condition:
    any of them
}