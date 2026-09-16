rule TTP_XOR_MULT_DOSStub_e6d7 {
  strings:
    $key_e6d7 = { b2 bf [2] c6 a7 [2] 81 a5 [2] c6 b4 [2] 88 b8 [2] 84 b2 [2] 93 b9 [2] 88 f7 [2] b5 }

  condition:
    any of them
}