rule TTP_XOR_MULT_DOSStub_a2b5 {
  strings:
    $key_a2b5 = { f6 dd [2] 82 c5 [2] c5 c7 [2] 82 d6 [2] cc da [2] c0 d0 [2] d7 db [2] cc 95 [2] f1 }

  condition:
    any of them
}