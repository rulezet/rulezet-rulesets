rule TTP_XOR_MULT_DOSStub_41d1 {
  strings:
    $key_41d1 = { 15 b9 [2] 61 a1 [2] 26 a3 [2] 61 b2 [2] 2f be [2] 23 b4 [2] 34 bf [2] 2f f1 [2] 12 }

  condition:
    any of them
}