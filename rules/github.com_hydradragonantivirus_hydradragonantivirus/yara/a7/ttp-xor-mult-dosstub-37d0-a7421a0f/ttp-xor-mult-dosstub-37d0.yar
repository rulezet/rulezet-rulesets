rule TTP_XOR_MULT_DOSStub_37d0 {
  strings:
    $key_37d0 = { 63 b8 [2] 17 a0 [2] 50 a2 [2] 17 b3 [2] 59 bf [2] 55 b5 [2] 42 be [2] 59 f0 [2] 64 }

  condition:
    any of them
}