rule TTP_XOR_MULT_DOSStub_76c3 {
  strings:
    $key_76c3 = { 22 ab [2] 56 b3 [2] 11 b1 [2] 56 a0 [2] 18 ac [2] 14 a6 [2] 03 ad [2] 18 e3 [2] 25 }

  condition:
    any of them
}