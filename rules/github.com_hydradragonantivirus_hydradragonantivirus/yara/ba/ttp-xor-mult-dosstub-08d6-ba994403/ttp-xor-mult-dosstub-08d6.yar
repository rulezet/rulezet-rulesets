rule TTP_XOR_MULT_DOSStub_08d6 {
  strings:
    $key_08d6 = { 5c be [2] 28 a6 [2] 6f a4 [2] 28 b5 [2] 66 b9 [2] 6a b3 [2] 7d b8 [2] 66 f6 [2] 5b }

  condition:
    any of them
}