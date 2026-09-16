rule TTP_XOR_MULT_DOSStub_b39e {
  strings:
    $key_b39e = { e7 f6 [2] 93 ee [2] d4 ec [2] 93 fd [2] dd f1 [2] d1 fb [2] c6 f0 [2] dd be [2] e0 }

  condition:
    any of them
}