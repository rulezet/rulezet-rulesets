rule TTP_XOR_MULT_DOSStub_20c5 {
  strings:
    $key_20c5 = { 74 ad [2] 00 b5 [2] 47 b7 [2] 00 a6 [2] 4e aa [2] 42 a0 [2] 55 ab [2] 4e e5 [2] 73 }

  condition:
    any of them
}