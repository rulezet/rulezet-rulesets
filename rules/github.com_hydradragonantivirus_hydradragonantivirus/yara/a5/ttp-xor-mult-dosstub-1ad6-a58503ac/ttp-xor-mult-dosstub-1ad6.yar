rule TTP_XOR_MULT_DOSStub_1ad6 {
  strings:
    $key_1ad6 = { 4e be [2] 3a a6 [2] 7d a4 [2] 3a b5 [2] 74 b9 [2] 78 b3 [2] 6f b8 [2] 74 f6 [2] 49 }

  condition:
    any of them
}