rule TTP_XOR_MULT_DOSStub_0dd6 {
  strings:
    $key_0dd6 = { 59 be [2] 2d a6 [2] 6a a4 [2] 2d b5 [2] 63 b9 [2] 6f b3 [2] 78 b8 [2] 63 f6 [2] 5e }

  condition:
    any of them
}