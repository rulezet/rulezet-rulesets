rule TTP_XOR_MULT_DOSStub_08d7 {
  strings:
    $key_08d7 = { 5c bf [2] 28 a7 [2] 6f a5 [2] 28 b4 [2] 66 b8 [2] 6a b2 [2] 7d b9 [2] 66 f7 [2] 5b }

  condition:
    any of them
}