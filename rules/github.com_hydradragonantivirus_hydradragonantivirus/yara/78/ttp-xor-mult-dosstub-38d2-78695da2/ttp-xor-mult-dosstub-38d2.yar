rule TTP_XOR_MULT_DOSStub_38d2 {
  strings:
    $key_38d2 = { 6c ba [2] 18 a2 [2] 5f a0 [2] 18 b1 [2] 56 bd [2] 5a b7 [2] 4d bc [2] 56 f2 [2] 6b }

  condition:
    any of them
}