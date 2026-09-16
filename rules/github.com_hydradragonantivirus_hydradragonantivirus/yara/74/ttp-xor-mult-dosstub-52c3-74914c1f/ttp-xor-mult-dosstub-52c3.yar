rule TTP_XOR_MULT_DOSStub_52c3 {
  strings:
    $key_52c3 = { 06 ab [2] 72 b3 [2] 35 b1 [2] 72 a0 [2] 3c ac [2] 30 a6 [2] 27 ad [2] 3c e3 [2] 01 }

  condition:
    any of them
}