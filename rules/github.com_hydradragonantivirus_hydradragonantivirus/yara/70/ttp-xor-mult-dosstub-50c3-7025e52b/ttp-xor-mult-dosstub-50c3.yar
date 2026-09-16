rule TTP_XOR_MULT_DOSStub_50c3 {
  strings:
    $key_50c3 = { 04 ab [2] 70 b3 [2] 37 b1 [2] 70 a0 [2] 3e ac [2] 32 a6 [2] 25 ad [2] 3e e3 [2] 03 }

  condition:
    any of them
}