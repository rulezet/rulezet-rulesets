rule TTP_XOR_MULT_DOSStub_0bb6 {
  strings:
    $key_0bb6 = { 5f de [2] 2b c6 [2] 6c c4 [2] 2b d5 [2] 65 d9 [2] 69 d3 [2] 7e d8 [2] 65 96 [2] 58 }

  condition:
    any of them
}