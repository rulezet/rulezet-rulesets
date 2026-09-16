rule TTP_XOR_MULT_DOSStub_c4d7 {
  strings:
    $key_c4d7 = { 90 bf [2] e4 a7 [2] a3 a5 [2] e4 b4 [2] aa b8 [2] a6 b2 [2] b1 b9 [2] aa f7 [2] 97 }

  condition:
    any of them
}