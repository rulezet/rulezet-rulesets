rule TTP_XOR_MULT_DOSStub_5ca1 {
  strings:
    $key_5ca1 = { 08 c9 [2] 7c d1 [2] 3b d3 [2] 7c c2 [2] 32 ce [2] 3e c4 [2] 29 cf [2] 32 81 [2] 0f }

  condition:
    any of them
}