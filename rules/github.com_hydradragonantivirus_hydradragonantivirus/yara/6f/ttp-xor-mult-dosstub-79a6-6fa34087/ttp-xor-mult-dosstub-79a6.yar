rule TTP_XOR_MULT_DOSStub_79a6 {
  strings:
    $key_79a6 = { 2d ce [2] 59 d6 [2] 1e d4 [2] 59 c5 [2] 17 c9 [2] 1b c3 [2] 0c c8 [2] 17 86 [2] 2a }

  condition:
    any of them
}