rule TTP_XOR_MULT_DOSStub_95ce {
  strings:
    $key_95ce = { c1 a6 [2] b5 be [2] f2 bc [2] b5 ad [2] fb a1 [2] f7 ab [2] e0 a0 [2] fb ee [2] c6 }

  condition:
    any of them
}