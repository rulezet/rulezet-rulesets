rule TTP_XOR_MULT_DOSStub_23c3 {
  strings:
    $key_23c3 = { 77 ab [2] 03 b3 [2] 44 b1 [2] 03 a0 [2] 4d ac [2] 41 a6 [2] 56 ad [2] 4d e3 [2] 70 }

  condition:
    any of them
}