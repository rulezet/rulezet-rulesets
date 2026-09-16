rule TTP_XOR_MULT_DOSStub_b586 {
  strings:
    $key_b586 = { e1 ee [2] 95 f6 [2] d2 f4 [2] 95 e5 [2] db e9 [2] d7 e3 [2] c0 e8 [2] db a6 [2] e6 }

  condition:
    any of them
}