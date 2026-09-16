rule TTP_XOR_MULT_DOSStub_b68b {
  strings:
    $key_b68b = { e2 e3 [2] 96 fb [2] d1 f9 [2] 96 e8 [2] d8 e4 [2] d4 ee [2] c3 e5 [2] d8 ab [2] e5 }

  condition:
    any of them
}