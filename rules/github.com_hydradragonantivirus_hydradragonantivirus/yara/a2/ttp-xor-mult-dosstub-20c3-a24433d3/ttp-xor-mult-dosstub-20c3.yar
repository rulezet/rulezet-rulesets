rule TTP_XOR_MULT_DOSStub_20c3 {
  strings:
    $key_20c3 = { 74 ab [2] 00 b3 [2] 47 b1 [2] 00 a0 [2] 4e ac [2] 42 a6 [2] 55 ad [2] 4e e3 [2] 73 }

  condition:
    any of them
}