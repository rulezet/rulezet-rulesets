rule TTP_XOR_MULT_DOSStub_5dd6 {
  strings:
    $key_5dd6 = { 09 be [2] 7d a6 [2] 3a a4 [2] 7d b5 [2] 33 b9 [2] 3f b3 [2] 28 b8 [2] 33 f6 [2] 0e }

  condition:
    any of them
}