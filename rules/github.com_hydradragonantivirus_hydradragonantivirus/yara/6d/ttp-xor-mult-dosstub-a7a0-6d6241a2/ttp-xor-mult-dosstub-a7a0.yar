rule TTP_XOR_MULT_DOSStub_a7a0 {
  strings:
    $key_a7a0 = { f3 c8 [2] 87 d0 [2] c0 d2 [2] 87 c3 [2] c9 cf [2] c5 c5 [2] d2 ce [2] c9 80 [2] f4 }

  condition:
    any of them
}