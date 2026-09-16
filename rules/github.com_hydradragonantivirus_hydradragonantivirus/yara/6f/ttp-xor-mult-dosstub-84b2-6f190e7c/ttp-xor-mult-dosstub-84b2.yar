rule TTP_XOR_MULT_DOSStub_84b2 {
  strings:
    $key_84b2 = { d0 da [2] a4 c2 [2] e3 c0 [2] a4 d1 [2] ea dd [2] e6 d7 [2] f1 dc [2] ea 92 [2] d7 }

  condition:
    any of them
}