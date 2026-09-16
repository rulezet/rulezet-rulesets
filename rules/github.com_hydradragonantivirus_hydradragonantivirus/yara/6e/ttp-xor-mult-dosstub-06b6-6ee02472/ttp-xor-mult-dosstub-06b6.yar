rule TTP_XOR_MULT_DOSStub_06b6 {
  strings:
    $key_06b6 = { 52 de [2] 26 c6 [2] 61 c4 [2] 26 d5 [2] 68 d9 [2] 64 d3 [2] 73 d8 [2] 68 96 [2] 55 }

  condition:
    any of them
}