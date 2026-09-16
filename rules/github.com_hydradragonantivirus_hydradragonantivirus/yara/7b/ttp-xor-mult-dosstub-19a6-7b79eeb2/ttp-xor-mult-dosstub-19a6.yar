rule TTP_XOR_MULT_DOSStub_19a6 {
  strings:
    $key_19a6 = { 4d ce [2] 39 d6 [2] 7e d4 [2] 39 c5 [2] 77 c9 [2] 7b c3 [2] 6c c8 [2] 77 86 [2] 4a }

  condition:
    any of them
}