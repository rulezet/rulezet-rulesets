rule TTP_XOR_MULT_DOSStub_a7b5 {
  strings:
    $key_a7b5 = { f3 dd [2] 87 c5 [2] c0 c7 [2] 87 d6 [2] c9 da [2] c5 d0 [2] d2 db [2] c9 95 [2] f4 }

  condition:
    any of them
}