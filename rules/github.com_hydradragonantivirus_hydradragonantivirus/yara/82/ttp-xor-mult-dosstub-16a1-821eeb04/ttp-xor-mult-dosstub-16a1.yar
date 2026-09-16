rule TTP_XOR_MULT_DOSStub_16a1 {
  strings:
    $key_16a1 = { 42 c9 [2] 36 d1 [2] 71 d3 [2] 36 c2 [2] 78 ce [2] 74 c4 [2] 63 cf [2] 78 81 [2] 45 }

  condition:
    any of them
}