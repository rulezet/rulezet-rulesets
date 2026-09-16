rule TTP_XOR_MULT_DOSStub_39a1 {
  strings:
    $key_39a1 = { 6d c9 [2] 19 d1 [2] 5e d3 [2] 19 c2 [2] 57 ce [2] 5b c4 [2] 4c cf [2] 57 81 [2] 6a }

  condition:
    any of them
}