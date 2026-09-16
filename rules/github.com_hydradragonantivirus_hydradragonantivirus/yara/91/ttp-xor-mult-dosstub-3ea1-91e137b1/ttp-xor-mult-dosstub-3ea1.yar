rule TTP_XOR_MULT_DOSStub_3ea1 {
  strings:
    $key_3ea1 = { 6a c9 [2] 1e d1 [2] 59 d3 [2] 1e c2 [2] 50 ce [2] 5c c4 [2] 4b cf [2] 50 81 [2] 6d }

  condition:
    any of them
}