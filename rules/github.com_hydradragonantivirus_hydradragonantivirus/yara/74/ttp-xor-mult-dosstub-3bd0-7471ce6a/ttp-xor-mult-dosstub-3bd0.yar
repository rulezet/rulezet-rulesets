rule TTP_XOR_MULT_DOSStub_3bd0 {
  strings:
    $key_3bd0 = { 6f b8 [2] 1b a0 [2] 5c a2 [2] 1b b3 [2] 55 bf [2] 59 b5 [2] 4e be [2] 55 f0 [2] 68 }

  condition:
    any of them
}