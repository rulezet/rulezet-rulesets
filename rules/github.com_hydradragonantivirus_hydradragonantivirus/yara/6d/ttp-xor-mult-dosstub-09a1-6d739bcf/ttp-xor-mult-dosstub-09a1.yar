rule TTP_XOR_MULT_DOSStub_09a1 {
  strings:
    $key_09a1 = { 5d c9 [2] 29 d1 [2] 6e d3 [2] 29 c2 [2] 67 ce [2] 6b c4 [2] 7c cf [2] 67 81 [2] 5a }

  condition:
    any of them
}