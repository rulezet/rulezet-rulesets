rule TTP_XOR_MULT_DOSStub_849a {
  strings:
    $key_849a = { d0 f2 [2] a4 ea [2] e3 e8 [2] a4 f9 [2] ea f5 [2] e6 ff [2] f1 f4 [2] ea ba [2] d7 }

  condition:
    any of them
}