rule TTP_XOR_MULT_DOSStub_87a0 {
  strings:
    $key_87a0 = { d3 c8 [2] a7 d0 [2] e0 d2 [2] a7 c3 [2] e9 cf [2] e5 c5 [2] f2 ce [2] e9 80 [2] d4 }

  condition:
    any of them
}