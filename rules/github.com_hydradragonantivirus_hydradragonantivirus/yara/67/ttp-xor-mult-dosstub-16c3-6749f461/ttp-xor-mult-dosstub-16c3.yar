rule TTP_XOR_MULT_DOSStub_16c3 {
  strings:
    $key_16c3 = { 42 ab [2] 36 b3 [2] 71 b1 [2] 36 a0 [2] 78 ac [2] 74 a6 [2] 63 ad [2] 78 e3 [2] 45 }

  condition:
    any of them
}