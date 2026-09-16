rule TTP_XOR_MULT_DOSStub_67d6 {
  strings:
    $key_67d6 = { 33 be [2] 47 a6 [2] 00 a4 [2] 47 b5 [2] 09 b9 [2] 05 b3 [2] 12 b8 [2] 09 f6 [2] 34 }

  condition:
    any of them
}