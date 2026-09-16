rule TTP_XOR_MULT_DOSStub_62c0 {
  strings:
    $key_62c0 = { 36 a8 [2] 42 b0 [2] 05 b2 [2] 42 a3 [2] 0c af [2] 00 a5 [2] 17 ae [2] 0c e0 [2] 31 }

  condition:
    any of them
}