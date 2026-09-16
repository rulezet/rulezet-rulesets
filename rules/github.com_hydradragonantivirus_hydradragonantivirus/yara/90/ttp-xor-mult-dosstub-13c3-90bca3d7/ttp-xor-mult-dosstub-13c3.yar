rule TTP_XOR_MULT_DOSStub_13c3 {
  strings:
    $key_13c3 = { 47 ab [2] 33 b3 [2] 74 b1 [2] 33 a0 [2] 7d ac [2] 71 a6 [2] 66 ad [2] 7d e3 [2] 40 }

  condition:
    any of them
}