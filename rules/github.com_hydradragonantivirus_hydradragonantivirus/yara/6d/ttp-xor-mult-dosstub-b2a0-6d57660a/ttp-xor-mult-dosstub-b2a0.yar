rule TTP_XOR_MULT_DOSStub_b2a0 {
  strings:
    $key_b2a0 = { e6 c8 [2] 92 d0 [2] d5 d2 [2] 92 c3 [2] dc cf [2] d0 c5 [2] c7 ce [2] dc 80 [2] e1 }

  condition:
    any of them
}