rule TTP_XOR_MULT_DOSStub_12c3 {
  strings:
    $key_12c3 = { 46 ab [2] 32 b3 [2] 75 b1 [2] 32 a0 [2] 7c ac [2] 70 a6 [2] 67 ad [2] 7c e3 [2] 41 }

  condition:
    any of them
}