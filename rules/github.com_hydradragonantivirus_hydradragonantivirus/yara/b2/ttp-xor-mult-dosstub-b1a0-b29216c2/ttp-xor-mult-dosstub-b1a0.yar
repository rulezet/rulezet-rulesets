rule TTP_XOR_MULT_DOSStub_b1a0 {
  strings:
    $key_b1a0 = { e5 c8 [2] 91 d0 [2] d6 d2 [2] 91 c3 [2] df cf [2] d3 c5 [2] c4 ce [2] df 80 [2] e2 }

  condition:
    any of them
}