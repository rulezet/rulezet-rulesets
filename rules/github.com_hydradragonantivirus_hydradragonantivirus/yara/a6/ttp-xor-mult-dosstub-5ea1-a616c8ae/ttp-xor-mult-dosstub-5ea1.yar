rule TTP_XOR_MULT_DOSStub_5ea1 {
  strings:
    $key_5ea1 = { 0a c9 [2] 7e d1 [2] 39 d3 [2] 7e c2 [2] 30 ce [2] 3c c4 [2] 2b cf [2] 30 81 [2] 0d }

  condition:
    any of them
}