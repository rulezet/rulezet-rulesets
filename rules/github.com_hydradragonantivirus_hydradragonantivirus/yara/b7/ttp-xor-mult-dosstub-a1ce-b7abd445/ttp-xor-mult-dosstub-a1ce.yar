rule TTP_XOR_MULT_DOSStub_a1ce {
  strings:
    $key_a1ce = { f5 a6 [2] 81 be [2] c6 bc [2] 81 ad [2] cf a1 [2] c3 ab [2] d4 a0 [2] cf ee [2] f2 }

  condition:
    any of them
}