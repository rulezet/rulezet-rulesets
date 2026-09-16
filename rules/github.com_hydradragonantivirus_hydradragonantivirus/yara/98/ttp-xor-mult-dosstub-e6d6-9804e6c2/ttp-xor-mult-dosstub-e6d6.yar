rule TTP_XOR_MULT_DOSStub_e6d6 {
  strings:
    $key_e6d6 = { b2 be [2] c6 a6 [2] 81 a4 [2] c6 b5 [2] 88 b9 [2] 84 b3 [2] 93 b8 [2] 88 f6 [2] b5 }

  condition:
    any of them
}