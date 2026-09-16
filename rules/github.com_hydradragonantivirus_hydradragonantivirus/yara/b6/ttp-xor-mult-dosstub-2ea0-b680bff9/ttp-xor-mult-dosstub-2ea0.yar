rule TTP_XOR_MULT_DOSStub_2ea0 {
  strings:
    $key_2ea0 = { 7a c8 [2] 0e d0 [2] 49 d2 [2] 0e c3 [2] 40 cf [2] 4c c5 [2] 5b ce [2] 40 80 [2] 7d }

  condition:
    any of them
}