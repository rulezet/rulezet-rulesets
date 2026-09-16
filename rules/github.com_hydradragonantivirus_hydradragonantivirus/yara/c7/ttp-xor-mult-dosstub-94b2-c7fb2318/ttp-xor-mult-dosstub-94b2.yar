rule TTP_XOR_MULT_DOSStub_94b2 {
  strings:
    $key_94b2 = { c0 da [2] b4 c2 [2] f3 c0 [2] b4 d1 [2] fa dd [2] f6 d7 [2] e1 dc [2] fa 92 [2] c7 }

  condition:
    any of them
}