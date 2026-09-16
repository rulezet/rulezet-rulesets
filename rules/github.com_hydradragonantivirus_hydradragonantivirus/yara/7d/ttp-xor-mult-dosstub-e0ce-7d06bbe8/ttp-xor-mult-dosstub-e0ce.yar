rule TTP_XOR_MULT_DOSStub_e0ce {
  strings:
    $key_e0ce = { b4 a6 [2] c0 be [2] 87 bc [2] c0 ad [2] 8e a1 [2] 82 ab [2] 95 a0 [2] 8e ee [2] b3 }

  condition:
    any of them
}