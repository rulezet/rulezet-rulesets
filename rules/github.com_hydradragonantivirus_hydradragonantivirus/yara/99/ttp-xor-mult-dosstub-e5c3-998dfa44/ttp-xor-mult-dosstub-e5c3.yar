rule TTP_XOR_MULT_DOSStub_e5c3 {
  strings:
    $key_e5c3 = { b1 ab [2] c5 b3 [2] 82 b1 [2] c5 a0 [2] 8b ac [2] 87 a6 [2] 90 ad [2] 8b e3 [2] b6 }

  condition:
    any of them
}