rule TTP_XOR_MULT_DOSStub_a2ce {
  strings:
    $key_a2ce = { f6 a6 [2] 82 be [2] c5 bc [2] 82 ad [2] cc a1 [2] c0 ab [2] d7 a0 [2] cc ee [2] f1 }

  condition:
    any of them
}