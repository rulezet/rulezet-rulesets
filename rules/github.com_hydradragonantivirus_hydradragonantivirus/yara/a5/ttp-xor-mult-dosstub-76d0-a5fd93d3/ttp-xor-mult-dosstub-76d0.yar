rule TTP_XOR_MULT_DOSStub_76d0 {
  strings:
    $key_76d0 = { 22 b8 [2] 56 a0 [2] 11 a2 [2] 56 b3 [2] 18 bf [2] 14 b5 [2] 03 be [2] 18 f0 [2] 25 }

  condition:
    any of them
}