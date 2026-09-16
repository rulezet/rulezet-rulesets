rule TTP_XOR_MULT_DOSStub_8588 {
  strings:
    $key_8588 = { d1 e0 [2] a5 f8 [2] e2 fa [2] a5 eb [2] eb e7 [2] e7 ed [2] f0 e6 [2] eb a8 [2] d6 }

  condition:
    any of them
}