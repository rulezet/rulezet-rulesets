rule TTP_XOR_MULT_DOSStub_3ad9 {
  strings:
    $key_3ad9 = { 6e b1 [2] 1a a9 [2] 5d ab [2] 1a ba [2] 54 b6 [2] 58 bc [2] 4f b7 [2] 54 f9 [2] 69 }

  condition:
    any of them
}