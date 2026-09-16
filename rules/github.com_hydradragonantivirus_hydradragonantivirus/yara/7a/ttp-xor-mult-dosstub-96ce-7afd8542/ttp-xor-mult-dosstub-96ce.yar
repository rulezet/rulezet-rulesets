rule TTP_XOR_MULT_DOSStub_96ce {
  strings:
    $key_96ce = { c2 a6 [2] b6 be [2] f1 bc [2] b6 ad [2] f8 a1 [2] f4 ab [2] e3 a0 [2] f8 ee [2] c5 }

  condition:
    any of them
}