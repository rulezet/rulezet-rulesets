rule TTP_XOR_MULT_DOSStub_2fd6 {
  strings:
    $key_2fd6 = { 7b be [2] 0f a6 [2] 48 a4 [2] 0f b5 [2] 41 b9 [2] 4d b3 [2] 5a b8 [2] 41 f6 [2] 7c }

  condition:
    any of them
}