rule TTP_XOR_MULT_DOSStub_73d0 {
  strings:
    $key_73d0 = { 27 b8 [2] 53 a0 [2] 14 a2 [2] 53 b3 [2] 1d bf [2] 11 b5 [2] 06 be [2] 1d f0 [2] 20 }

  condition:
    any of them
}