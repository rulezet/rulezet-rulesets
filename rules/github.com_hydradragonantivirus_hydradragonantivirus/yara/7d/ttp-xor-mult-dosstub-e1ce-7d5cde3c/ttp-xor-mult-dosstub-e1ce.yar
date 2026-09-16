rule TTP_XOR_MULT_DOSStub_e1ce {
  strings:
    $key_e1ce = { b5 a6 [2] c1 be [2] 86 bc [2] c1 ad [2] 8f a1 [2] 83 ab [2] 94 a0 [2] 8f ee [2] b2 }

  condition:
    any of them
}