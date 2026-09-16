rule TTP_XOR_MULT_DOSStub_4bd0 {
  strings:
    $key_4bd0 = { 1f b8 [2] 6b a0 [2] 2c a2 [2] 6b b3 [2] 25 bf [2] 29 b5 [2] 3e be [2] 25 f0 [2] 18 }

  condition:
    any of them
}