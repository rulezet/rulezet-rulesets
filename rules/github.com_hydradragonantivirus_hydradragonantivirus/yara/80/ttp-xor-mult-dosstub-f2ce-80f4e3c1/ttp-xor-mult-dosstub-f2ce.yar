rule TTP_XOR_MULT_DOSStub_f2ce {
  strings:
    $key_f2ce = { a6 a6 [2] d2 be [2] 95 bc [2] d2 ad [2] 9c a1 [2] 90 ab [2] 87 a0 [2] 9c ee [2] a1 }

  condition:
    any of them
}