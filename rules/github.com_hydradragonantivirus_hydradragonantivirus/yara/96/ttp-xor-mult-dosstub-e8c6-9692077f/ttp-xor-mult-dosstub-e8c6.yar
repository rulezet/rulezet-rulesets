rule TTP_XOR_MULT_DOSStub_e8c6 {
  strings:
    $key_e8c6 = { bc ae [2] c8 b6 [2] 8f b4 [2] c8 a5 [2] 86 a9 [2] 8a a3 [2] 9d a8 [2] 86 e6 [2] bb }

  condition:
    any of them
}