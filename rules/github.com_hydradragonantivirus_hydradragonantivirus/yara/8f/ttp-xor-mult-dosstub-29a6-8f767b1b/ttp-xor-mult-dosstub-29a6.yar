rule TTP_XOR_MULT_DOSStub_29a6 {
  strings:
    $key_29a6 = { 7d ce [2] 09 d6 [2] 4e d4 [2] 09 c5 [2] 47 c9 [2] 4b c3 [2] 5c c8 [2] 47 86 [2] 7a }

  condition:
    any of them
}