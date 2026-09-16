rule TTP_XOR_MULT_DOSStub_0ea6 {
  strings:
    $key_0ea6 = { 5a ce [2] 2e d6 [2] 69 d4 [2] 2e c5 [2] 60 c9 [2] 6c c3 [2] 7b c8 [2] 60 86 [2] 5d }

  condition:
    any of them
}