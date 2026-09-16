rule TTP_XOR_MULT_DOSStub_1787 {
  strings:
    $key_1787 = { 43 ef [2] 37 f7 [2] 70 f5 [2] 37 e4 [2] 79 e8 [2] 75 e2 [2] 62 e9 [2] 79 a7 [2] 44 }

  condition:
    any of them
}