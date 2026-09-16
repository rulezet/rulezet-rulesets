rule TTP_XOR_MULT_DOSStub_25c0 {
  strings:
    $key_25c0 = { 71 a8 [2] 05 b0 [2] 42 b2 [2] 05 a3 [2] 4b af [2] 47 a5 [2] 50 ae [2] 4b e0 [2] 76 }

  condition:
    any of them
}