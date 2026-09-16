rule TTP_XOR_MULT_DOSStub_84d4 {
  strings:
    $key_84d4 = { d0 bc [2] a4 a4 [2] e3 a6 [2] a4 b7 [2] ea bb [2] e6 b1 [2] f1 ba [2] ea f4 [2] d7 }

  condition:
    any of them
}