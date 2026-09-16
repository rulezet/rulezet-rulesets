rule TTP_XOR_MULT_DOSStub_0fd6 {
  strings:
    $key_0fd6 = { 5b be [2] 2f a6 [2] 68 a4 [2] 2f b5 [2] 61 b9 [2] 6d b3 [2] 7a b8 [2] 61 f6 [2] 5c }

  condition:
    any of them
}