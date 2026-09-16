rule TTP_XOR_MULT_DOSStub_7ea1 {
  strings:
    $key_7ea1 = { 2a c9 [2] 5e d1 [2] 19 d3 [2] 5e c2 [2] 10 ce [2] 1c c4 [2] 0b cf [2] 10 81 [2] 2d }

  condition:
    any of them
}