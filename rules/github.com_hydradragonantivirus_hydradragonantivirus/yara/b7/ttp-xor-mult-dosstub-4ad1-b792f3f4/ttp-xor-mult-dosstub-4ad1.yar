rule TTP_XOR_MULT_DOSStub_4ad1 {
  strings:
    $key_4ad1 = { 1e b9 [2] 6a a1 [2] 2d a3 [2] 6a b2 [2] 24 be [2] 28 b4 [2] 3f bf [2] 24 f1 [2] 19 }

  condition:
    any of them
}