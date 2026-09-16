rule TTP_XOR_MULT_DOSStub_5fd9 {
  strings:
    $key_5fd9 = { 0b b1 [2] 7f a9 [2] 38 ab [2] 7f ba [2] 31 b6 [2] 3d bc [2] 2a b7 [2] 31 f9 [2] 0c }

  condition:
    any of them
}