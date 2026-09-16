rule TTP_XOR_MULT_DOSStub_18d2 {
  strings:
    $key_18d2 = { 4c ba [2] 38 a2 [2] 7f a0 [2] 38 b1 [2] 76 bd [2] 7a b7 [2] 6d bc [2] 76 f2 [2] 4b }

  condition:
    any of them
}