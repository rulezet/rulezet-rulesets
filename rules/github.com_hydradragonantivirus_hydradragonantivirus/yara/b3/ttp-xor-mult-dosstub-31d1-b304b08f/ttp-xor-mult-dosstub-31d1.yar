rule TTP_XOR_MULT_DOSStub_31d1 {
  strings:
    $key_31d1 = { 65 b9 [2] 11 a1 [2] 56 a3 [2] 11 b2 [2] 5f be [2] 53 b4 [2] 44 bf [2] 5f f1 [2] 62 }

  condition:
    any of them
}