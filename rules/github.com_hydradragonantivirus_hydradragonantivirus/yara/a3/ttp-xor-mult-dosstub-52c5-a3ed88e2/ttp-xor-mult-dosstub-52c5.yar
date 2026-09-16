rule TTP_XOR_MULT_DOSStub_52c5 {
  strings:
    $key_52c5 = { 06 ad [2] 72 b5 [2] 35 b7 [2] 72 a6 [2] 3c aa [2] 30 a0 [2] 27 ab [2] 3c e5 [2] 01 }

  condition:
    any of them
}