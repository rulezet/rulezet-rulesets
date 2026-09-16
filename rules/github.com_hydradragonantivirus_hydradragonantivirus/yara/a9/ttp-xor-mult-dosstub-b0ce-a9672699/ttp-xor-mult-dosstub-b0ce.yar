rule TTP_XOR_MULT_DOSStub_b0ce {
  strings:
    $key_b0ce = { e4 a6 [2] 90 be [2] d7 bc [2] 90 ad [2] de a1 [2] d2 ab [2] c5 a0 [2] de ee [2] e3 }

  condition:
    any of them
}