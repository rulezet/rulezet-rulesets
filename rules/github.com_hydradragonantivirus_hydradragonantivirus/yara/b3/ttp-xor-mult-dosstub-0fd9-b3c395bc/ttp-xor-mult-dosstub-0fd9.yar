rule TTP_XOR_MULT_DOSStub_0fd9 {
  strings:
    $key_0fd9 = { 5b b1 [2] 2f a9 [2] 68 ab [2] 2f ba [2] 61 b6 [2] 6d bc [2] 7a b7 [2] 61 f9 [2] 5c }

  condition:
    any of them
}