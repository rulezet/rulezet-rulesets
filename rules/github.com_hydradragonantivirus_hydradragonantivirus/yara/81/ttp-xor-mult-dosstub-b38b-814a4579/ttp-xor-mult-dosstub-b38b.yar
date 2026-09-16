rule TTP_XOR_MULT_DOSStub_b38b {
  strings:
    $key_b38b = { e7 e3 [2] 93 fb [2] d4 f9 [2] 93 e8 [2] dd e4 [2] d1 ee [2] c6 e5 [2] dd ab [2] e0 }

  condition:
    any of them
}