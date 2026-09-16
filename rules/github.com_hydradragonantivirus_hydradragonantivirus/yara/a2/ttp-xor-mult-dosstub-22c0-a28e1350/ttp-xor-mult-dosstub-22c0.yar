rule TTP_XOR_MULT_DOSStub_22c0 {
  strings:
    $key_22c0 = { 76 a8 [2] 02 b0 [2] 45 b2 [2] 02 a3 [2] 4c af [2] 40 a5 [2] 57 ae [2] 4c e0 [2] 71 }

  condition:
    any of them
}