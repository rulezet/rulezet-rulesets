rule TTP_XOR_MULT_DOSStub_66d0 {
  strings:
    $key_66d0 = { 32 b8 [2] 46 a0 [2] 01 a2 [2] 46 b3 [2] 08 bf [2] 04 b5 [2] 13 be [2] 08 f0 [2] 35 }

  condition:
    any of them
}