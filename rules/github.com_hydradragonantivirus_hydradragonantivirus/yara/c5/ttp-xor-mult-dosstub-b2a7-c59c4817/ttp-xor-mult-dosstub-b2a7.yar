rule TTP_XOR_MULT_DOSStub_b2a7 {
  strings:
    $key_b2a7 = { e6 cf [2] 92 d7 [2] d5 d5 [2] 92 c4 [2] dc c8 [2] d0 c2 [2] c7 c9 [2] dc 87 [2] e1 }

  condition:
    any of them
}