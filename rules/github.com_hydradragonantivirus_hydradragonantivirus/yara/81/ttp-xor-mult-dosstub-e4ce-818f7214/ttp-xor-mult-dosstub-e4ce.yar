rule TTP_XOR_MULT_DOSStub_e4ce {
  strings:
    $key_e4ce = { b0 a6 [2] c4 be [2] 83 bc [2] c4 ad [2] 8a a1 [2] 86 ab [2] 91 a0 [2] 8a ee [2] b7 }

  condition:
    any of them
}