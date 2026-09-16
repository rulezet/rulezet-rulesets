rule TTP_XOR_MULT_DOSStub_b3b5 {
  strings:
    $key_b3b5 = { e7 dd [2] 93 c5 [2] d4 c7 [2] 93 d6 [2] dd da [2] d1 d0 [2] c6 db [2] dd 95 [2] e0 }

  condition:
    any of them
}