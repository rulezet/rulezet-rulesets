rule TTP_XOR_MULT_DOSStub_dc9e {
  strings:
    $key_dc9e = { 88 f6 [2] fc ee [2] bb ec [2] fc fd [2] b2 f1 [2] be fb [2] a9 f0 [2] b2 be [2] 8f }

  condition:
    any of them
}