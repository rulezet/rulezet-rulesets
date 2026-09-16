rule TTP_XOR_MULT_DOSStub_b5b4 {
  strings:
    $key_b5b4 = { e1 dc [2] 95 c4 [2] d2 c6 [2] 95 d7 [2] db db [2] d7 d1 [2] c0 da [2] db 94 [2] e6 }

  condition:
    any of them
}