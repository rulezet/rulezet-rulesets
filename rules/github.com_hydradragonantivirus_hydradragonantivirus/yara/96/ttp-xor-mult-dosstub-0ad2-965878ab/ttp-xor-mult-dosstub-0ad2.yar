rule TTP_XOR_MULT_DOSStub_0ad2 {
  strings:
    $key_0ad2 = { 5e ba [2] 2a a2 [2] 6d a0 [2] 2a b1 [2] 64 bd [2] 68 b7 [2] 7f bc [2] 64 f2 [2] 59 }

  condition:
    any of them
}