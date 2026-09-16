rule TTP_XOR_MULT_DOSStub_e6b5 {
  strings:
    $key_e6b5 = { b2 dd [2] c6 c5 [2] 81 c7 [2] c6 d6 [2] 88 da [2] 84 d0 [2] 93 db [2] 88 95 [2] b5 }

  condition:
    any of them
}