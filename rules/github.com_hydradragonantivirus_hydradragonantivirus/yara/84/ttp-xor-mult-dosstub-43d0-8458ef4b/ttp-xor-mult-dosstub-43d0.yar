rule TTP_XOR_MULT_DOSStub_43d0 {
  strings:
    $key_43d0 = { 17 b8 [2] 63 a0 [2] 24 a2 [2] 63 b3 [2] 2d bf [2] 21 b5 [2] 36 be [2] 2d f0 [2] 10 }

  condition:
    any of them
}