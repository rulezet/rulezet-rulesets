rule TTP_XOR_MULT_DOSStub_05c3 {
  strings:
    $key_05c3 = { 51 ab [2] 25 b3 [2] 62 b1 [2] 25 a0 [2] 6b ac [2] 67 a6 [2] 70 ad [2] 6b e3 [2] 56 }

  condition:
    any of them
}