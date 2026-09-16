rule TTP_XOR_MULT_DOSStub_05d7 {
  strings:
    $key_05d7 = { 51 bf [2] 25 a7 [2] 62 a5 [2] 25 b4 [2] 6b b8 [2] 67 b2 [2] 70 b9 [2] 6b f7 [2] 56 }

  condition:
    any of them
}