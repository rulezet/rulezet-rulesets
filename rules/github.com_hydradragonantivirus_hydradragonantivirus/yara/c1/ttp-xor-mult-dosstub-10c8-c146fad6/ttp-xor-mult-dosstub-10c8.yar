rule TTP_XOR_MULT_DOSStub_10c8 {
  strings:
    $key_10c8 = { 44 a0 [2] 30 b8 [2] 77 ba [2] 30 ab [2] 7e a7 [2] 72 ad [2] 65 a6 [2] 7e e8 [2] 43 }

  condition:
    any of them
}