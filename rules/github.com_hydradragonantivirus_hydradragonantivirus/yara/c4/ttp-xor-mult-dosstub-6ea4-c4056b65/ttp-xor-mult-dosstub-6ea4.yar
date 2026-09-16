rule TTP_XOR_MULT_DOSStub_6ea4 {
  strings:
    $key_6ea4 = { 3a cc [2] 4e d4 [2] 09 d6 [2] 4e c7 [2] 00 cb [2] 0c c1 [2] 1b ca [2] 00 84 [2] 3d }

  condition:
    any of them
}