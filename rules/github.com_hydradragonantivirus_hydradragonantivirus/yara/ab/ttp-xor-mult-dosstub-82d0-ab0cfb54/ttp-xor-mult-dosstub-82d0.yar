rule TTP_XOR_MULT_DOSStub_82d0 {
  strings:
    $key_82d0 = { d6 b8 [2] a2 a0 [2] e5 a2 [2] a2 b3 [2] ec bf [2] e0 b5 [2] f7 be [2] ec f0 [2] d1 }

  condition:
    any of them
}