rule TTP_XOR_MULT_DOSStub_f8c2 {
  strings:
    $key_f8c2 = { ac aa [2] d8 b2 [2] 9f b0 [2] d8 a1 [2] 96 ad [2] 9a a7 [2] 8d ac [2] 96 e2 [2] ab }

  condition:
    any of them
}