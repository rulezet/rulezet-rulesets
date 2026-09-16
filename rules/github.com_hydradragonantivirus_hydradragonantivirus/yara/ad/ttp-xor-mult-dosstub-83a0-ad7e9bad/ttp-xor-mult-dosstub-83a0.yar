rule TTP_XOR_MULT_DOSStub_83a0 {
  strings:
    $key_83a0 = { d7 c8 [2] a3 d0 [2] e4 d2 [2] a3 c3 [2] ed cf [2] e1 c5 [2] f6 ce [2] ed 80 [2] d0 }

  condition:
    any of them
}