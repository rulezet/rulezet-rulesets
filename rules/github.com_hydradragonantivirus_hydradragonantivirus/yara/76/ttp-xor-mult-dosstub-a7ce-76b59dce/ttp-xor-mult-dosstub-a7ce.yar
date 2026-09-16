rule TTP_XOR_MULT_DOSStub_a7ce {
  strings:
    $key_a7ce = { f3 a6 [2] 87 be [2] c0 bc [2] 87 ad [2] c9 a1 [2] c5 ab [2] d2 a0 [2] c9 ee [2] f4 }

  condition:
    any of them
}