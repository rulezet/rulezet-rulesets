rule TTP_XOR_MULT_DOSStub_2dd6 {
  strings:
    $key_2dd6 = { 79 be [2] 0d a6 [2] 4a a4 [2] 0d b5 [2] 43 b9 [2] 4f b3 [2] 58 b8 [2] 43 f6 [2] 7e }

  condition:
    any of them
}