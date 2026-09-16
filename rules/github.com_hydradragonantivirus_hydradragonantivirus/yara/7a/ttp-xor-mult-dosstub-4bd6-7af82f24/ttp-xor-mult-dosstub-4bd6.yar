rule TTP_XOR_MULT_DOSStub_4bd6 {
  strings:
    $key_4bd6 = { 1f be [2] 6b a6 [2] 2c a4 [2] 6b b5 [2] 25 b9 [2] 29 b3 [2] 3e b8 [2] 25 f6 [2] 18 }

  condition:
    any of them
}