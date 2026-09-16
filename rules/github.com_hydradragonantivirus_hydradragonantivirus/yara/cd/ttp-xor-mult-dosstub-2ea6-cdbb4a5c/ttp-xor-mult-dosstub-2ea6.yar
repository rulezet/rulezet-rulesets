rule TTP_XOR_MULT_DOSStub_2ea6 {
  strings:
    $key_2ea6 = { 7a ce [2] 0e d6 [2] 49 d4 [2] 0e c5 [2] 40 c9 [2] 4c c3 [2] 5b c8 [2] 40 86 [2] 7d }

  condition:
    any of them
}