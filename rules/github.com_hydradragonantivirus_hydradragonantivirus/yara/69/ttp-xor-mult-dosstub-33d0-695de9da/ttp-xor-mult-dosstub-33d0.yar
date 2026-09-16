rule TTP_XOR_MULT_DOSStub_33d0 {
  strings:
    $key_33d0 = { 67 b8 [2] 13 a0 [2] 54 a2 [2] 13 b3 [2] 5d bf [2] 51 b5 [2] 46 be [2] 5d f0 [2] 60 }

  condition:
    any of them
}