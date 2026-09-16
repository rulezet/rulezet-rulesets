rule TTP_XOR_MULT_DOSStub_84b3 {
  strings:
    $key_84b3 = { d0 db [2] a4 c3 [2] e3 c1 [2] a4 d0 [2] ea dc [2] e6 d6 [2] f1 dd [2] ea 93 [2] d7 }

  condition:
    any of them
}