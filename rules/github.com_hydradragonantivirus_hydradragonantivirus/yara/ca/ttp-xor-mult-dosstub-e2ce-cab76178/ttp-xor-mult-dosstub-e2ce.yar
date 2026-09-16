rule TTP_XOR_MULT_DOSStub_e2ce {
  strings:
    $key_e2ce = { b6 a6 [2] c2 be [2] 85 bc [2] c2 ad [2] 8c a1 [2] 80 ab [2] 97 a0 [2] 8c ee [2] b1 }

  condition:
    any of them
}