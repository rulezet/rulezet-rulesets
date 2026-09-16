rule TTP_XOR_MULT_DOSStub_84d0 {
  strings:
    $key_84d0 = { d0 b8 [2] a4 a0 [2] e3 a2 [2] a4 b3 [2] ea bf [2] e6 b5 [2] f1 be [2] ea f0 [2] d7 }

  condition:
    any of them
}