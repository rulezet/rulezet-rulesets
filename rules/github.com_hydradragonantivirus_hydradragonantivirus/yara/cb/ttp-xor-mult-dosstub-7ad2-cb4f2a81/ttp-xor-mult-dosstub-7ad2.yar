rule TTP_XOR_MULT_DOSStub_7ad2 {
  strings:
    $key_7ad2 = { 2e ba [2] 5a a2 [2] 1d a0 [2] 5a b1 [2] 14 bd [2] 18 b7 [2] 0f bc [2] 14 f2 [2] 29 }

  condition:
    any of them
}