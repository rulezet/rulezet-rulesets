rule TTP_XOR_MULT_DOSStub_e6b2 {
  strings:
    $key_e6b2 = { b2 da [2] c6 c2 [2] 81 c0 [2] c6 d1 [2] 88 dd [2] 84 d7 [2] 93 dc [2] 88 92 [2] b5 }

  condition:
    any of them
}