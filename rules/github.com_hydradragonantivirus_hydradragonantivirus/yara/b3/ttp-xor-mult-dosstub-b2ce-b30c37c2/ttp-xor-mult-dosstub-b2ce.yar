rule TTP_XOR_MULT_DOSStub_b2ce {
  strings:
    $key_b2ce = { e6 a6 [2] 92 be [2] d5 bc [2] 92 ad [2] dc a1 [2] d0 ab [2] c7 a0 [2] dc ee [2] e1 }

  condition:
    any of them
}