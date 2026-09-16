rule TTP_XOR_MULT_DOSStub_b1a7 {
  strings:
    $key_b1a7 = { e5 cf [2] 91 d7 [2] d6 d5 [2] 91 c4 [2] df c8 [2] d3 c2 [2] c4 c9 [2] df 87 [2] e2 }

  condition:
    any of them
}