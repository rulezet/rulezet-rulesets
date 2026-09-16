rule TTP_XOR_MULT_DOSStub_82c1 {
  strings:
    $key_82c1 = { d6 a9 [2] a2 b1 [2] e5 b3 [2] a2 a2 [2] ec ae [2] e0 a4 [2] f7 af [2] ec e1 [2] d1 }

  condition:
    any of them
}