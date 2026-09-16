rule TTP_XOR_MULT_DOSStub_a7d0 {
  strings:
    $key_a7d0 = { f3 b8 [2] 87 a0 [2] c0 a2 [2] 87 b3 [2] c9 bf [2] c5 b5 [2] d2 be [2] c9 f0 [2] f4 }

  condition:
    any of them
}