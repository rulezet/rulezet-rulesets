rule TTP_XOR_MULT_DOSStub_08a0 {
  strings:
    $key_08a0 = { 5c c8 [2] 28 d0 [2] 6f d2 [2] 28 c3 [2] 66 cf [2] 6a c5 [2] 7d ce [2] 66 80 [2] 5b }

  condition:
    any of them
}