rule TTP_XOR_MULT_DOSStub_49a6 {
  strings:
    $key_49a6 = { 1d ce [2] 69 d6 [2] 2e d4 [2] 69 c5 [2] 27 c9 [2] 2b c3 [2] 3c c8 [2] 27 86 [2] 1a }

  condition:
    any of them
}