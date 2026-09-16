rule TTP_XOR_MULT_DOSStub_82a0 {
  strings:
    $key_82a0 = { d6 c8 [2] a2 d0 [2] e5 d2 [2] a2 c3 [2] ec cf [2] e0 c5 [2] f7 ce [2] ec 80 [2] d1 }

  condition:
    any of them
}