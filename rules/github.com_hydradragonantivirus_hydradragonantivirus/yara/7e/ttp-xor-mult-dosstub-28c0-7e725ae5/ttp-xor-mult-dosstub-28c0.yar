rule TTP_XOR_MULT_DOSStub_28c0 {
  strings:
    $key_28c0 = { 7c a8 [2] 08 b0 [2] 4f b2 [2] 08 a3 [2] 46 af [2] 4a a5 [2] 5d ae [2] 46 e0 [2] 7b }

  condition:
    any of them
}