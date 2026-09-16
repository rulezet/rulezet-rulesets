rule TTP_XOR_MULT_DOSStub_30c8 {
  strings:
    $key_30c8 = { 64 a0 [2] 10 b8 [2] 57 ba [2] 10 ab [2] 5e a7 [2] 52 ad [2] 45 a6 [2] 5e e8 [2] 63 }

  condition:
    any of them
}