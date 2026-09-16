rule TTP_XOR_MULT_DOSStub_38c2 {
  strings:
    $key_38c2 = { 6c aa [2] 18 b2 [2] 5f b0 [2] 18 a1 [2] 56 ad [2] 5a a7 [2] 4d ac [2] 56 e2 [2] 6b }

  condition:
    any of them
}