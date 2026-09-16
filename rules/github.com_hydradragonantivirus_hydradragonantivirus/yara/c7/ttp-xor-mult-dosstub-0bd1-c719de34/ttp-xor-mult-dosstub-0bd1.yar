rule TTP_XOR_MULT_DOSStub_0bd1 {
  strings:
    $key_0bd1 = { 5f b9 [2] 2b a1 [2] 6c a3 [2] 2b b2 [2] 65 be [2] 69 b4 [2] 7e bf [2] 65 f1 [2] 58 }

  condition:
    any of them
}