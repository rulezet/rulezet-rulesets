rule TTP_XOR_MULT_DOSStub_3fd9 {
  strings:
    $key_3fd9 = { 6b b1 [2] 1f a9 [2] 58 ab [2] 1f ba [2] 51 b6 [2] 5d bc [2] 4a b7 [2] 51 f9 [2] 6c }

  condition:
    any of them
}