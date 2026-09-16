rule TTP_XOR_MULT_DOSStub_e8c2 {
  strings:
    $key_e8c2 = { bc aa [2] c8 b2 [2] 8f b0 [2] c8 a1 [2] 86 ad [2] 8a a7 [2] 9d ac [2] 86 e2 [2] bb }

  condition:
    any of them
}