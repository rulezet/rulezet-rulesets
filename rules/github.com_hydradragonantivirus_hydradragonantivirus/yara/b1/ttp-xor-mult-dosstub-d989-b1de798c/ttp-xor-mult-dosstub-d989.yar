rule TTP_XOR_MULT_DOSStub_d989 {
  strings:
    $key_d989 = { 8d e1 [2] f9 f9 [2] be fb [2] f9 ea [2] b7 e6 [2] bb ec [2] ac e7 [2] b7 a9 [2] 8a }

  condition:
    any of them
}