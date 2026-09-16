rule TTP_XOR_MULT_DOSStub_b588 {
  strings:
    $key_b588 = { e1 e0 [2] 95 f8 [2] d2 fa [2] 95 eb [2] db e7 [2] d7 ed [2] c0 e6 [2] db a8 [2] e6 }

  condition:
    any of them
}