rule TTP_XOR_MULT_DOSStub_b6b4 {
  strings:
    $key_b6b4 = { e2 dc [2] 96 c4 [2] d1 c6 [2] 96 d7 [2] d8 db [2] d4 d1 [2] c3 da [2] d8 94 [2] e5 }

  condition:
    any of them
}