rule TTP_XOR_MULT_DOSStub_1ea1 {
  strings:
    $key_1ea1 = { 4a c9 [2] 3e d1 [2] 79 d3 [2] 3e c2 [2] 70 ce [2] 7c c4 [2] 6b cf [2] 70 81 [2] 4d }

  condition:
    any of them
}