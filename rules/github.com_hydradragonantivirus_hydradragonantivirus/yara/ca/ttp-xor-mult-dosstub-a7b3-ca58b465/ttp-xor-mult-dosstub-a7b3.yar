rule TTP_XOR_MULT_DOSStub_a7b3 {
  strings:
    $key_a7b3 = { f3 db [2] 87 c3 [2] c0 c1 [2] 87 d0 [2] c9 dc [2] c5 d6 [2] d2 dd [2] c9 93 [2] f4 }

  condition:
    any of them
}