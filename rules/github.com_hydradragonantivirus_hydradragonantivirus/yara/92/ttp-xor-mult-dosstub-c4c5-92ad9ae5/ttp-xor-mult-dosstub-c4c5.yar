rule TTP_XOR_MULT_DOSStub_c4c5 {
  strings:
    $key_c4c5 = { 90 ad [2] e4 b5 [2] a3 b7 [2] e4 a6 [2] aa aa [2] a6 a0 [2] b1 ab [2] aa e5 [2] 97 }

  condition:
    any of them
}