rule TTP_XOR_MULT_DOSStub_13c8 {
  strings:
    $key_13c8 = { 47 a0 [2] 33 b8 [2] 74 ba [2] 33 ab [2] 7d a7 [2] 71 ad [2] 66 a6 [2] 7d e8 [2] 40 }

  condition:
    any of them
}