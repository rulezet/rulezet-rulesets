rule TTP_XOR_MULT_DOSStub_69d1 {
  strings:
    $key_69d1 = { 3d b9 [2] 49 a1 [2] 0e a3 [2] 49 b2 [2] 07 be [2] 0b b4 [2] 1c bf [2] 07 f1 [2] 3a }

  condition:
    any of them
}