rule TTP_XOR_MULT_DOSStub_b698 {
  strings:
    $key_b698 = { e2 f0 [2] 96 e8 [2] d1 ea [2] 96 fb [2] d8 f7 [2] d4 fd [2] c3 f6 [2] d8 b8 [2] e5 }

  condition:
    any of them
}