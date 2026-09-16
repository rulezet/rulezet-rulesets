rule TTP_XOR_MULT_DOSStub_e8c7 {
  strings:
    $key_e8c7 = { bc af [2] c8 b7 [2] 8f b5 [2] c8 a4 [2] 86 a8 [2] 8a a2 [2] 9d a9 [2] 86 e7 [2] bb }

  condition:
    any of them
}