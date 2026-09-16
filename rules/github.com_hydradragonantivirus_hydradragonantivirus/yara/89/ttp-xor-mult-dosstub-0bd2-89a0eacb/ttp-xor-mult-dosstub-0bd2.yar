rule TTP_XOR_MULT_DOSStub_0bd2 {
  strings:
    $key_0bd2 = { 5f ba [2] 2b a2 [2] 6c a0 [2] 2b b1 [2] 65 bd [2] 69 b7 [2] 7e bc [2] 65 f2 [2] 58 }

  condition:
    any of them
}