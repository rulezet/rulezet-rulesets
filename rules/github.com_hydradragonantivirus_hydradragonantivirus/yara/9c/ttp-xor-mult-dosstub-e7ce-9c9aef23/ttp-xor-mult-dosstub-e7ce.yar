rule TTP_XOR_MULT_DOSStub_e7ce {
  strings:
    $key_e7ce = { b3 a6 [2] c7 be [2] 80 bc [2] c7 ad [2] 89 a1 [2] 85 ab [2] 92 a0 [2] 89 ee [2] b4 }

  condition:
    any of them
}