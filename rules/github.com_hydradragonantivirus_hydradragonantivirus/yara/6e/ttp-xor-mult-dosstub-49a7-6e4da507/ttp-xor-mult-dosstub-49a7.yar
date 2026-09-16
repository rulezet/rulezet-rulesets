rule TTP_XOR_MULT_DOSStub_49a7 {
  strings:
    $key_49a7 = { 1d cf [2] 69 d7 [2] 2e d5 [2] 69 c4 [2] 27 c8 [2] 2b c2 [2] 3c c9 [2] 27 87 [2] 1a }

  condition:
    any of them
}