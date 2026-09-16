rule TTP_XOR_MULT_DOSStub_25c3 {
  strings:
    $key_25c3 = { 71 ab [2] 05 b3 [2] 42 b1 [2] 05 a0 [2] 4b ac [2] 47 a6 [2] 50 ad [2] 4b e3 [2] 76 }

  condition:
    any of them
}