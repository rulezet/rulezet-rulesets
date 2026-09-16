rule TTP_XOR_MULT_DOSStub_b581 {
  strings:
    $key_b581 = { e1 e9 [2] 95 f1 [2] d2 f3 [2] 95 e2 [2] db ee [2] d7 e4 [2] c0 ef [2] db a1 [2] e6 }

  condition:
    any of them
}