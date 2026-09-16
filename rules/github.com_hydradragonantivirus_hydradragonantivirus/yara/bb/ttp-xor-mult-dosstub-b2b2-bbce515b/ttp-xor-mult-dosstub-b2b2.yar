rule TTP_XOR_MULT_DOSStub_b2b2 {
  strings:
    $key_b2b2 = { e6 da [2] 92 c2 [2] d5 c0 [2] 92 d1 [2] dc dd [2] d0 d7 [2] c7 dc [2] dc 92 [2] e1 }

  condition:
    any of them
}