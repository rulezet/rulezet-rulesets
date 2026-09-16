rule TTP_XOR_MULT_DOSStub_7bd2 {
  strings:
    $key_7bd2 = { 2f ba [2] 5b a2 [2] 1c a0 [2] 5b b1 [2] 15 bd [2] 19 b7 [2] 0e bc [2] 15 f2 [2] 28 }

  condition:
    any of them
}