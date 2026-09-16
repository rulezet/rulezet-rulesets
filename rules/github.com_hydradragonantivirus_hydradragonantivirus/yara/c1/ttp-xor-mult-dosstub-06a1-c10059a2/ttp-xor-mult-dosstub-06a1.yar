rule TTP_XOR_MULT_DOSStub_06a1 {
  strings:
    $key_06a1 = { 52 c9 [2] 26 d1 [2] 61 d3 [2] 26 c2 [2] 68 ce [2] 64 c4 [2] 73 cf [2] 68 81 [2] 55 }

  condition:
    any of them
}