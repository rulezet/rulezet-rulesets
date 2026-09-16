rule TTP_XOR_MULT_DOSStub_7ad7 {
  strings:
    $key_7ad7 = { 2e bf [2] 5a a7 [2] 1d a5 [2] 5a b4 [2] 14 b8 [2] 18 b2 [2] 0f b9 [2] 14 f7 [2] 29 }

  condition:
    any of them
}