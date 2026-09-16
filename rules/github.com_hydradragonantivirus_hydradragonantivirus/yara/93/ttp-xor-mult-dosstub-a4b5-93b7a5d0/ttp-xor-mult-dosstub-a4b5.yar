rule TTP_XOR_MULT_DOSStub_a4b5 {
  strings:
    $key_a4b5 = { f0 dd [2] 84 c5 [2] c3 c7 [2] 84 d6 [2] ca da [2] c6 d0 [2] d1 db [2] ca 95 [2] f7 }

  condition:
    any of them
}