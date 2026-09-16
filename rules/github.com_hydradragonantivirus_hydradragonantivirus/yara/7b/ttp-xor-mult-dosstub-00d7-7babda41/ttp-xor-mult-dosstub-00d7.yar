rule TTP_XOR_MULT_DOSStub_00d7 {
  strings:
    $key_00d7 = { 54 bf [2] 20 a7 [2] 67 a5 [2] 20 b4 [2] 6e b8 [2] 62 b2 [2] 75 b9 [2] 6e f7 [2] 53 }

  condition:
    any of them
}