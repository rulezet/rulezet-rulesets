rule TTP_XOR_MULT_DOSStub_04c5 {
  strings:
    $key_04c5 = { 50 ad [2] 24 b5 [2] 63 b7 [2] 24 a6 [2] 6a aa [2] 66 a0 [2] 71 ab [2] 6a e5 [2] 57 }

  condition:
    any of them
}