rule TTP_XOR_MULT_DOSStub_33c8 {
  strings:
    $key_33c8 = { 67 a0 [2] 13 b8 [2] 54 ba [2] 13 ab [2] 5d a7 [2] 51 ad [2] 46 a6 [2] 5d e8 [2] 60 }

  condition:
    any of them
}