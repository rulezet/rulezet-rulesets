rule TTP_XOR_MULT_DOSStub_c4d1 {
  strings:
    $key_c4d1 = { 90 b9 [2] e4 a1 [2] a3 a3 [2] e4 b2 [2] aa be [2] a6 b4 [2] b1 bf [2] aa f1 [2] 97 }

  condition:
    any of them
}