rule TTP_XOR_MULT_DOSStub_8485 {
  strings:
    $key_8485 = { d0 ed [2] a4 f5 [2] e3 f7 [2] a4 e6 [2] ea ea [2] e6 e0 [2] f1 eb [2] ea a5 [2] d7 }

  condition:
    any of them
}