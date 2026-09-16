rule TTP_XOR_MULT_DOSStub_32c3 {
  strings:
    $key_32c3 = { 66 ab [2] 12 b3 [2] 55 b1 [2] 12 a0 [2] 5c ac [2] 50 a6 [2] 47 ad [2] 5c e3 [2] 61 }

  condition:
    any of them
}