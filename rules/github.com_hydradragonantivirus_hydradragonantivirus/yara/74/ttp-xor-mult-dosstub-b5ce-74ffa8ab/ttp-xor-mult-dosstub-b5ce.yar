rule TTP_XOR_MULT_DOSStub_b5ce {
  strings:
    $key_b5ce = { e1 a6 [2] 95 be [2] d2 bc [2] 95 ad [2] db a1 [2] d7 ab [2] c0 a0 [2] db ee [2] e6 }

  condition:
    any of them
}