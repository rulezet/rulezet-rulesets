rule TTP_XOR_MULT_DOSStub_e5c0 {
  strings:
    $key_e5c0 = { b1 a8 [2] c5 b0 [2] 82 b2 [2] c5 a3 [2] 8b af [2] 87 a5 [2] 90 ae [2] 8b e0 [2] b6 }

  condition:
    any of them
}