rule TTP_XOR_MULT_DOSStub_d5ce {
  strings:
    $key_d5ce = { 81 a6 [2] f5 be [2] b2 bc [2] f5 ad [2] bb a1 [2] b7 ab [2] a0 a0 [2] bb ee [2] 86 }

  condition:
    any of them
}