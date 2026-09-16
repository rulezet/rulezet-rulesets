rule TTP_XOR_MULT_DOSStub_f2c5 {
  strings:
    $key_f2c5 = { a6 ad [2] d2 b5 [2] 95 b7 [2] d2 a6 [2] 9c aa [2] 90 a0 [2] 87 ab [2] 9c e5 [2] a1 }

  condition:
    any of them
}