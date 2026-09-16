rule TTP_XOR_MULT_DOSStub_5bb6 {
  strings:
    $key_5bb6 = { 0f de [2] 7b c6 [2] 3c c4 [2] 7b d5 [2] 35 d9 [2] 39 d3 [2] 2e d8 [2] 35 96 [2] 08 }

  condition:
    any of them
}