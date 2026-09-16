rule TTP_XOR_MULT_DOSStub_63d0 {
  strings:
    $key_63d0 = { 37 b8 [2] 43 a0 [2] 04 a2 [2] 43 b3 [2] 0d bf [2] 01 b5 [2] 16 be [2] 0d f0 [2] 30 }

  condition:
    any of them
}