rule TTP_XOR_MULT_DOSStub_72c5 {
  strings:
    $key_72c5 = { 26 ad [2] 52 b5 [2] 15 b7 [2] 52 a6 [2] 1c aa [2] 10 a0 [2] 07 ab [2] 1c e5 [2] 21 }

  condition:
    any of them
}