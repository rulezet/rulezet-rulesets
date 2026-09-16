rule TTP_XOR_MULT_DOSStub_e1b3 {
  strings:
    $key_e1b3 = { b5 db [2] c1 c3 [2] 86 c1 [2] c1 d0 [2] 8f dc [2] 83 d6 [2] 94 dd [2] 8f 93 [2] b2 }

  condition:
    any of them
}