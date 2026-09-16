rule TTP_XOR_MULT_DOSStub_4ea1 {
  strings:
    $key_4ea1 = { 1a c9 [2] 6e d1 [2] 29 d3 [2] 6e c2 [2] 20 ce [2] 2c c4 [2] 3b cf [2] 20 81 [2] 1d }

  condition:
    any of them
}