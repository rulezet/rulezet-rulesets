rule TTP_XOR_MULT_DOSStub_e1b5 {
  strings:
    $key_e1b5 = { b5 dd [2] c1 c5 [2] 86 c7 [2] c1 d6 [2] 8f da [2] 83 d0 [2] 94 db [2] 8f 95 [2] b2 }

  condition:
    any of them
}