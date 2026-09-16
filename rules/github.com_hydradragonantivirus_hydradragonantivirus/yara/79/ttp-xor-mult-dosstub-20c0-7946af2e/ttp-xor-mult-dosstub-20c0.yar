rule TTP_XOR_MULT_DOSStub_20c0 {
  strings:
    $key_20c0 = { 74 a8 [2] 00 b0 [2] 47 b2 [2] 00 a3 [2] 4e af [2] 42 a5 [2] 55 ae [2] 4e e0 [2] 73 }

  condition:
    any of them
}