rule TTP_XOR_MULT_DOSStub_ead3 {
  strings:
    $key_ead3 = { be bb [2] ca a3 [2] 8d a1 [2] ca b0 [2] 84 bc [2] 88 b6 [2] 9f bd [2] 84 f3 [2] b9 }

  condition:
    any of them
}