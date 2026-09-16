rule TTP_XOR_MULT_DOSStub_e6d0 {
  strings:
    $key_e6d0 = { b2 b8 [2] c6 a0 [2] 81 a2 [2] c6 b3 [2] 88 bf [2] 84 b5 [2] 93 be [2] 88 f0 [2] b5 }

  condition:
    any of them
}