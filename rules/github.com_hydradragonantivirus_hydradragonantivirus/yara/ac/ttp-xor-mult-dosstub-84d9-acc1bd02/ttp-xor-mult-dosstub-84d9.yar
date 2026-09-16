rule TTP_XOR_MULT_DOSStub_84d9 {
  strings:
    $key_84d9 = { d0 b1 [2] a4 a9 [2] e3 ab [2] a4 ba [2] ea b6 [2] e6 bc [2] f1 b7 [2] ea f9 [2] d7 }

  condition:
    any of them
}