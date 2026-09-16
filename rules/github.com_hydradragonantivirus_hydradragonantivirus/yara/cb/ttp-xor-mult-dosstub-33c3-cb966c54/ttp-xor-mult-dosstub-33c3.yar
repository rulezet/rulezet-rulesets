rule TTP_XOR_MULT_DOSStub_33c3 {
  strings:
    $key_33c3 = { 67 ab [2] 13 b3 [2] 54 b1 [2] 13 a0 [2] 5d ac [2] 51 a6 [2] 46 ad [2] 5d e3 [2] 60 }

  condition:
    any of them
}