rule TTP_XOR_MULT_DOSStub_94d1 {
  strings:
    $key_94d1 = { c0 b9 [2] b4 a1 [2] f3 a3 [2] b4 b2 [2] fa be [2] f6 b4 [2] e1 bf [2] fa f1 [2] c7 }

  condition:
    any of them
}