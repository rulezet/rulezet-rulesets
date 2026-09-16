rule TTP_XOR_MULT_DOSStub_b6b3 {
  strings:
    $key_b6b3 = { e2 db [2] 96 c3 [2] d1 c1 [2] 96 d0 [2] d8 dc [2] d4 d6 [2] c3 dd [2] d8 93 [2] e5 }

  condition:
    any of them
}