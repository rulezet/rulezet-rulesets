rule TTP_XOR_MULT_DOSStub_e1b9 {
  strings:
    $key_e1b9 = { b5 d1 [2] c1 c9 [2] 86 cb [2] c1 da [2] 8f d6 [2] 83 dc [2] 94 d7 [2] 8f 99 [2] b2 }

  condition:
    any of them
}