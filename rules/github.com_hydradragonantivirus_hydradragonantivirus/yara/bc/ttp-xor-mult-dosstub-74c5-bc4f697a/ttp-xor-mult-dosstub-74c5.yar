rule TTP_XOR_MULT_DOSStub_74c5 {
  strings:
    $key_74c5 = { 20 ad [2] 54 b5 [2] 13 b7 [2] 54 a6 [2] 1a aa [2] 16 a0 [2] 01 ab [2] 1a e5 [2] 27 }

  condition:
    any of them
}