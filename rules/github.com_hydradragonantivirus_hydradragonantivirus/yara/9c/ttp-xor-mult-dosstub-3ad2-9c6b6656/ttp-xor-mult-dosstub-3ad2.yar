rule TTP_XOR_MULT_DOSStub_3ad2 {
  strings:
    $key_3ad2 = { 6e ba [2] 1a a2 [2] 5d a0 [2] 1a b1 [2] 54 bd [2] 58 b7 [2] 4f bc [2] 54 f2 [2] 69 }

  condition:
    any of them
}