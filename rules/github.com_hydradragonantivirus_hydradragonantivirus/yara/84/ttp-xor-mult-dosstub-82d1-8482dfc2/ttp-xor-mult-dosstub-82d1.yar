rule TTP_XOR_MULT_DOSStub_82d1 {
  strings:
    $key_82d1 = { d6 b9 [2] a2 a1 [2] e5 a3 [2] a2 b2 [2] ec be [2] e0 b4 [2] f7 bf [2] ec f1 [2] d1 }

  condition:
    any of them
}