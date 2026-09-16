rule TTP_XOR_MULT_DOSStub_84c8 {
  strings:
    $key_84c8 = { d0 a0 [2] a4 b8 [2] e3 ba [2] a4 ab [2] ea a7 [2] e6 ad [2] f1 a6 [2] ea e8 [2] d7 }

  condition:
    any of them
}