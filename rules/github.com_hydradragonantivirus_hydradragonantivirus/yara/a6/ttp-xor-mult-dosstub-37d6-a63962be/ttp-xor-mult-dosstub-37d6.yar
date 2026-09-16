rule TTP_XOR_MULT_DOSStub_37d6 {
  strings:
    $key_37d6 = { 63 be [2] 17 a6 [2] 50 a4 [2] 17 b5 [2] 59 b9 [2] 55 b3 [2] 42 b8 [2] 59 f6 [2] 64 }

  condition:
    any of them
}