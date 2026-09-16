rule TTP_XOR_MULT_DOSStub_03c3 {
  strings:
    $key_03c3 = { 57 ab [2] 23 b3 [2] 64 b1 [2] 23 a0 [2] 6d ac [2] 61 a6 [2] 76 ad [2] 6d e3 [2] 50 }

  condition:
    any of them
}