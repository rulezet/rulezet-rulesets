rule TTP_XOR_MULT_DOSStub_38d3 {
  strings:
    $key_38d3 = { 6c bb [2] 18 a3 [2] 5f a1 [2] 18 b0 [2] 56 bc [2] 5a b6 [2] 4d bd [2] 56 f3 [2] 6b }

  condition:
    any of them
}