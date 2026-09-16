rule TTP_XOR_MULT_DOSStub_27d7 {
  strings:
    $key_27d7 = { 73 bf [2] 07 a7 [2] 40 a5 [2] 07 b4 [2] 49 b8 [2] 45 b2 [2] 52 b9 [2] 49 f7 [2] 74 }

  condition:
    any of them
}