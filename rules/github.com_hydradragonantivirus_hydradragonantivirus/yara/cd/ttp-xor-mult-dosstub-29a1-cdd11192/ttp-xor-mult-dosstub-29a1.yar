rule TTP_XOR_MULT_DOSStub_29a1 {
  strings:
    $key_29a1 = { 7d c9 [2] 09 d1 [2] 4e d3 [2] 09 c2 [2] 47 ce [2] 4b c4 [2] 5c cf [2] 47 81 [2] 7a }

  condition:
    any of them
}