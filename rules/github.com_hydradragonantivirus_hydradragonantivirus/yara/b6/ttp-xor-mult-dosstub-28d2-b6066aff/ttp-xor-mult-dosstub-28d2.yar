rule TTP_XOR_MULT_DOSStub_28d2 {
  strings:
    $key_28d2 = { 7c ba [2] 08 a2 [2] 4f a0 [2] 08 b1 [2] 46 bd [2] 4a b7 [2] 5d bc [2] 46 f2 [2] 7b }

  condition:
    any of them
}