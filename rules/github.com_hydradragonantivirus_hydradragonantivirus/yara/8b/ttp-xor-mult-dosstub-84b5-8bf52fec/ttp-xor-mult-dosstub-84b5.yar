rule TTP_XOR_MULT_DOSStub_84b5 {
  strings:
    $key_84b5 = { d0 dd [2] a4 c5 [2] e3 c7 [2] a4 d6 [2] ea da [2] e6 d0 [2] f1 db [2] ea 95 [2] d7 }

  condition:
    any of them
}