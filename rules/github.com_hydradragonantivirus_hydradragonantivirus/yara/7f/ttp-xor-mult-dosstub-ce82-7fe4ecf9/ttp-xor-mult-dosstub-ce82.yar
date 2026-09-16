rule TTP_XOR_MULT_DOSStub_ce82 {
  strings:
    $key_ce82 = { 9a ea [2] ee f2 [2] a9 f0 [2] ee e1 [2] a0 ed [2] ac e7 [2] bb ec [2] a0 a2 [2] 9d }

  condition:
    any of them
}