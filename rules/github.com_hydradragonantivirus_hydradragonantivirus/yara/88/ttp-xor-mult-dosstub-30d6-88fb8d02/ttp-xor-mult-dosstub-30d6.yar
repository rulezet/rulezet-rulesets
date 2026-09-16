rule TTP_XOR_MULT_DOSStub_30d6 {
  strings:
    $key_30d6 = { 64 be [2] 10 a6 [2] 57 a4 [2] 10 b5 [2] 5e b9 [2] 52 b3 [2] 45 b8 [2] 5e f6 [2] 63 }

  condition:
    any of them
}