rule TTP_XOR_MULT_DOSStub_7bd0 {
  strings:
    $key_7bd0 = { 2f b8 [2] 5b a0 [2] 1c a2 [2] 5b b3 [2] 15 bf [2] 19 b5 [2] 0e be [2] 15 f0 [2] 28 }

  condition:
    any of them
}