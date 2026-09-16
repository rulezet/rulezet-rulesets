rule TTP_XOR_MULT_DOSStub_7ea4 {
  strings:
    $key_7ea4 = { 2a cc [2] 5e d4 [2] 19 d6 [2] 5e c7 [2] 10 cb [2] 1c c1 [2] 0b ca [2] 10 84 [2] 2d }

  condition:
    any of them
}