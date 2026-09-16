rule TTP_XOR_MULT_DOSStub_84a2 {
  strings:
    $key_84a2 = { d0 ca [2] a4 d2 [2] e3 d0 [2] a4 c1 [2] ea cd [2] e6 c7 [2] f1 cc [2] ea 82 [2] d7 }

  condition:
    any of them
}