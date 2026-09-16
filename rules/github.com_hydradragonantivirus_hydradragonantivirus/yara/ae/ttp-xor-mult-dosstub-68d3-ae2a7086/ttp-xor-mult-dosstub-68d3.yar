rule TTP_XOR_MULT_DOSStub_68d3 {
  strings:
    $key_68d3 = { 3c bb [2] 48 a3 [2] 0f a1 [2] 48 b0 [2] 06 bc [2] 0a b6 [2] 1d bd [2] 06 f3 [2] 3b }

  condition:
    any of them
}