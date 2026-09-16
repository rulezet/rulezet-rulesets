rule TTP_XOR_MULT_DOSStub_92ce {
  strings:
    $key_92ce = { c6 a6 [2] b2 be [2] f5 bc [2] b2 ad [2] fc a1 [2] f0 ab [2] e7 a0 [2] fc ee [2] c1 }

  condition:
    any of them
}