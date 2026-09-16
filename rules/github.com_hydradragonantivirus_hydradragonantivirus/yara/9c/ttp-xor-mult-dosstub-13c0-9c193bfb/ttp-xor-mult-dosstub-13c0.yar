rule TTP_XOR_MULT_DOSStub_13c0 {
  strings:
    $key_13c0 = { 47 a8 [2] 33 b0 [2] 74 b2 [2] 33 a3 [2] 7d af [2] 71 a5 [2] 66 ae [2] 7d e0 [2] 40 }

  condition:
    any of them
}