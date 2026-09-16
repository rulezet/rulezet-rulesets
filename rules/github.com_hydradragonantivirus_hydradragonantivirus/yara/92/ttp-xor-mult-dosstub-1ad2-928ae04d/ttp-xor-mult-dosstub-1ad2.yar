rule TTP_XOR_MULT_DOSStub_1ad2 {
  strings:
    $key_1ad2 = { 4e ba [2] 3a a2 [2] 7d a0 [2] 3a b1 [2] 74 bd [2] 78 b7 [2] 6f bc [2] 74 f2 [2] 49 }

  condition:
    any of them
}