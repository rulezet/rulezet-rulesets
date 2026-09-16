rule TTP_XOR_MULT_DOSStub_18d3 {
  strings:
    $key_18d3 = { 4c bb [2] 38 a3 [2] 7f a1 [2] 38 b0 [2] 76 bc [2] 7a b6 [2] 6d bd [2] 76 f3 [2] 4b }

  condition:
    any of them
}