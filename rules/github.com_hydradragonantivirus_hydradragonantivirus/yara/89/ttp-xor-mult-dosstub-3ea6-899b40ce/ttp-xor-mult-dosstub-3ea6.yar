rule TTP_XOR_MULT_DOSStub_3ea6 {
  strings:
    $key_3ea6 = { 6a ce [2] 1e d6 [2] 59 d4 [2] 1e c5 [2] 50 c9 [2] 5c c3 [2] 4b c8 [2] 50 86 [2] 6d }

  condition:
    any of them
}