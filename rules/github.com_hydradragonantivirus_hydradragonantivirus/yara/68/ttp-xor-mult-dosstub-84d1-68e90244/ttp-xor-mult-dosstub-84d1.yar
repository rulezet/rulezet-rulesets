rule TTP_XOR_MULT_DOSStub_84d1 {
  strings:
    $key_84d1 = { d0 b9 [2] a4 a1 [2] e3 a3 [2] a4 b2 [2] ea be [2] e6 b4 [2] f1 bf [2] ea f1 [2] d7 }

  condition:
    any of them
}