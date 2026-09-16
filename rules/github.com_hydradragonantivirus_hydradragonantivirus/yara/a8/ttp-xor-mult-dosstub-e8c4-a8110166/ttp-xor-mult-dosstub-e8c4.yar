rule TTP_XOR_MULT_DOSStub_e8c4 {
  strings:
    $key_e8c4 = { bc ac [2] c8 b4 [2] 8f b6 [2] c8 a7 [2] 86 ab [2] 8a a1 [2] 9d aa [2] 86 e4 [2] bb }

  condition:
    any of them
}