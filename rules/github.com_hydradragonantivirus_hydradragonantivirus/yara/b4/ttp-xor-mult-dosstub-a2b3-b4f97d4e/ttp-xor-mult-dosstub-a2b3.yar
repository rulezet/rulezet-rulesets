rule TTP_XOR_MULT_DOSStub_a2b3 {
  strings:
    $key_a2b3 = { f6 db [2] 82 c3 [2] c5 c1 [2] 82 d0 [2] cc dc [2] c0 d6 [2] d7 dd [2] cc 93 [2] f1 }

  condition:
    any of them
}