rule TTP_XOR_MULT_DOSStub_12c8 {
  strings:
    $key_12c8 = { 46 a0 [2] 32 b8 [2] 75 ba [2] 32 ab [2] 7c a7 [2] 70 ad [2] 67 a6 [2] 7c e8 [2] 41 }

  condition:
    any of them
}