rule TTP_XOR_MULT_DOSStub_67a1 {
  strings:
    $key_67a1 = { 33 c9 [2] 47 d1 [2] 00 d3 [2] 47 c2 [2] 09 ce [2] 05 c4 [2] 12 cf [2] 09 81 [2] 34 }

  condition:
    any of them
}