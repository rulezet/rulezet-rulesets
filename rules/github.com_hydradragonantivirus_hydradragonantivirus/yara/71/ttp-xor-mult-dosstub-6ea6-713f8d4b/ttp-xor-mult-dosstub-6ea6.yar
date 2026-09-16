rule TTP_XOR_MULT_DOSStub_6ea6 {
  strings:
    $key_6ea6 = { 3a ce [2] 4e d6 [2] 09 d4 [2] 4e c5 [2] 00 c9 [2] 0c c3 [2] 1b c8 [2] 00 86 [2] 3d }

  condition:
    any of them
}