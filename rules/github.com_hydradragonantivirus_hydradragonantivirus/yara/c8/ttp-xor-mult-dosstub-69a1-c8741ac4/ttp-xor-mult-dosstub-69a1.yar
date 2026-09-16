rule TTP_XOR_MULT_DOSStub_69a1 {
  strings:
    $key_69a1 = { 3d c9 [2] 49 d1 [2] 0e d3 [2] 49 c2 [2] 07 ce [2] 0b c4 [2] 1c cf [2] 07 81 [2] 3a }

  condition:
    any of them
}