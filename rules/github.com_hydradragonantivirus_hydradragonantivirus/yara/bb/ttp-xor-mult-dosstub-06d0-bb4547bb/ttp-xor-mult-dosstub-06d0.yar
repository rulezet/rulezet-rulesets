rule TTP_XOR_MULT_DOSStub_06d0 {
  strings:
    $key_06d0 = { 52 b8 [2] 26 a0 [2] 61 a2 [2] 26 b3 [2] 68 bf [2] 64 b5 [2] 73 be [2] 68 f0 [2] 55 }

  condition:
    any of them
}