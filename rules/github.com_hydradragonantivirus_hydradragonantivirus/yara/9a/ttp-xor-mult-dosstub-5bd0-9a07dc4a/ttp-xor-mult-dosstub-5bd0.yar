rule TTP_XOR_MULT_DOSStub_5bd0 {
  strings:
    $key_5bd0 = { 0f b8 [2] 7b a0 [2] 3c a2 [2] 7b b3 [2] 35 bf [2] 39 b5 [2] 2e be [2] 35 f0 [2] 08 }

  condition:
    any of them
}