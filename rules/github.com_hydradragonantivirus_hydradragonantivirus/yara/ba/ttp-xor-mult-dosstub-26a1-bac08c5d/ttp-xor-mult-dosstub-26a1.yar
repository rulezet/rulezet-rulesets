rule TTP_XOR_MULT_DOSStub_26a1 {
  strings:
    $key_26a1 = { 72 c9 [2] 06 d1 [2] 41 d3 [2] 06 c2 [2] 48 ce [2] 44 c4 [2] 53 cf [2] 48 81 [2] 75 }

  condition:
    any of them
}