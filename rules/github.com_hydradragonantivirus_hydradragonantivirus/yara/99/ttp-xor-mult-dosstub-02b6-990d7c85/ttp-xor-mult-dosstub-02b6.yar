rule TTP_XOR_MULT_DOSStub_02b6 {
  strings:
    $key_02b6 = { 56 de [2] 22 c6 [2] 65 c4 [2] 22 d5 [2] 6c d9 [2] 60 d3 [2] 77 d8 [2] 6c 96 [2] 51 }

  condition:
    any of them
}