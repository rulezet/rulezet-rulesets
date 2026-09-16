rule TTP_XOR_MULT_DOSStub_18c0 {
  strings:
    $key_18c0 = { 4c a8 [2] 38 b0 [2] 7f b2 [2] 38 a3 [2] 76 af [2] 7a a5 [2] 6d ae [2] 76 e0 [2] 4b }

  condition:
    any of them
}