rule TTP_XOR_MULT_DOSStub_32c8 {
  strings:
    $key_32c8 = { 66 a0 [2] 12 b8 [2] 55 ba [2] 12 ab [2] 5c a7 [2] 50 ad [2] 47 a6 [2] 5c e8 [2] 61 }

  condition:
    any of them
}