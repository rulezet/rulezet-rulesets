rule TTP_XOR_MULT_DOSStub_e6b4 {
  strings:
    $key_e6b4 = { b2 dc [2] c6 c4 [2] 81 c6 [2] c6 d7 [2] 88 db [2] 84 d1 [2] 93 da [2] 88 94 [2] b5 }

  condition:
    any of them
}