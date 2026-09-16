rule TTP_XOR_MULT_DOSStub_73c3 {
  strings:
    $key_73c3 = { 27 ab [2] 53 b3 [2] 14 b1 [2] 53 a0 [2] 1d ac [2] 11 a6 [2] 06 ad [2] 1d e3 [2] 20 }

  condition:
    any of them
}