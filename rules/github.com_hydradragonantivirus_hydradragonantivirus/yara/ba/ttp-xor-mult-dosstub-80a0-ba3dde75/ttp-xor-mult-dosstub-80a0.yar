rule TTP_XOR_MULT_DOSStub_80a0 {
  strings:
    $key_80a0 = { d4 c8 [2] a0 d0 [2] e7 d2 [2] a0 c3 [2] ee cf [2] e2 c5 [2] f5 ce [2] ee 80 [2] d3 }

  condition:
    any of them
}