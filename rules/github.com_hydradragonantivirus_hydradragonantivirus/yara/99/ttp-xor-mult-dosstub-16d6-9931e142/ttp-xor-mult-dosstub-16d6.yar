rule TTP_XOR_MULT_DOSStub_16d6 {
  strings:
    $key_16d6 = { 42 be [2] 36 a6 [2] 71 a4 [2] 36 b5 [2] 78 b9 [2] 74 b3 [2] 63 b8 [2] 78 f6 [2] 45 }

  condition:
    any of them
}