rule TTP_XOR_MULT_DOSStub_60d0 {
  strings:
    $key_60d0 = { 34 b8 [2] 40 a0 [2] 07 a2 [2] 40 b3 [2] 0e bf [2] 02 b5 [2] 15 be [2] 0e f0 [2] 33 }

  condition:
    any of them
}