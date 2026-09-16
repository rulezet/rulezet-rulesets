rule TTP_XOR_MULT_DOSStub_97d0 {
  strings:
    $key_97d0 = { c3 b8 [2] b7 a0 [2] f0 a2 [2] b7 b3 [2] f9 bf [2] f5 b5 [2] e2 be [2] f9 f0 [2] c4 }

  condition:
    any of them
}