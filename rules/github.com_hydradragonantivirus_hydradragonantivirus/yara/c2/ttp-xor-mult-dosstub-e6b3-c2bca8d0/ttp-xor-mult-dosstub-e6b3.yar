rule TTP_XOR_MULT_DOSStub_e6b3 {
  strings:
    $key_e6b3 = { b2 db [2] c6 c3 [2] 81 c1 [2] c6 d0 [2] 88 dc [2] 84 d6 [2] 93 dd [2] 88 93 [2] b5 }

  condition:
    any of them
}