rule TTP_XOR_MULT_DOSStub_12c0 {
  strings:
    $key_12c0 = { 46 a8 [2] 32 b0 [2] 75 b2 [2] 32 a3 [2] 7c af [2] 70 a5 [2] 67 ae [2] 7c e0 [2] 41 }

  condition:
    any of them
}