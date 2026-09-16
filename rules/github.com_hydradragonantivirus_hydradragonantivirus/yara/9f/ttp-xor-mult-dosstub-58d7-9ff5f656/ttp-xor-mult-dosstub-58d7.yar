rule TTP_XOR_MULT_DOSStub_58d7 {
  strings:
    $key_58d7 = { 0c bf [2] 78 a7 [2] 3f a5 [2] 78 b4 [2] 36 b8 [2] 3a b2 [2] 2d b9 [2] 36 f7 [2] 0b }

  condition:
    any of them
}