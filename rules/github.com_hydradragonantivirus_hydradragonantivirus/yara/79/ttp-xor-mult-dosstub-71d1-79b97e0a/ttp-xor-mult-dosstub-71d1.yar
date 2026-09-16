rule TTP_XOR_MULT_DOSStub_71d1 {
  strings:
    $key_71d1 = { 25 b9 [2] 51 a1 [2] 16 a3 [2] 51 b2 [2] 1f be [2] 13 b4 [2] 04 bf [2] 1f f1 [2] 22 }

  condition:
    any of them
}