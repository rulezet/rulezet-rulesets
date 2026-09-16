rule TTP_XOR_MULT_DOSStub_a6b5 {
  strings:
    $key_a6b5 = { f2 dd [2] 86 c5 [2] c1 c7 [2] 86 d6 [2] c8 da [2] c4 d0 [2] d3 db [2] c8 95 [2] f5 }

  condition:
    any of them
}