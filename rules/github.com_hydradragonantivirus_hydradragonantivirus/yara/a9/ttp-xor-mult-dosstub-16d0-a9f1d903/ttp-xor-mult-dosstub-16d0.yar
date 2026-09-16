rule TTP_XOR_MULT_DOSStub_16d0 {
  strings:
    $key_16d0 = { 42 b8 [2] 36 a0 [2] 71 a2 [2] 36 b3 [2] 78 bf [2] 74 b5 [2] 63 be [2] 78 f0 [2] 45 }

  condition:
    any of them
}