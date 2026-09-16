rule TTP_XOR_MULT_DOSStub_16c8 {
  strings:
    $key_16c8 = { 42 a0 [2] 36 b8 [2] 71 ba [2] 36 ab [2] 78 a7 [2] 74 ad [2] 63 a6 [2] 78 e8 [2] 45 }

  condition:
    any of them
}