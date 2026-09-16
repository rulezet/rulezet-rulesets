rule TTP_XOR_MULT_DOSStub_86ce {
  strings:
    $key_86ce = { d2 a6 [2] a6 be [2] e1 bc [2] a6 ad [2] e8 a1 [2] e4 ab [2] f3 a0 [2] e8 ee [2] d5 }

  condition:
    any of them
}