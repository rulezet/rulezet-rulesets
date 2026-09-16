rule TTP_XOR_MULT_DOSStub_21ce {
  strings:
    $key_21ce = { 75 a6 [2] 01 be [2] 46 bc [2] 01 ad [2] 4f a1 [2] 43 ab [2] 54 a0 [2] 4f ee [2] 72 }

  condition:
    any of them
}