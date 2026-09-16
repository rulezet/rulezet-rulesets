rule TTP_XOR_MULT_DOSStub_8491 {
  strings:
    $key_8491 = { d0 f9 [2] a4 e1 [2] e3 e3 [2] a4 f2 [2] ea fe [2] e6 f4 [2] f1 ff [2] ea b1 [2] d7 }

  condition:
    any of them
}