rule TTP_XOR_MULT_DOSStub_6bd0 {
  strings:
    $key_6bd0 = { 3f b8 [2] 4b a0 [2] 0c a2 [2] 4b b3 [2] 05 bf [2] 09 b5 [2] 1e be [2] 05 f0 [2] 38 }

  condition:
    any of them
}