rule TTP_XOR_MULT_DOSStub_8384 {
  strings:
    $key_8384 = { d7 ec [2] a3 f4 [2] e4 f6 [2] a3 e7 [2] ed eb [2] e1 e1 [2] f6 ea [2] ed a4 [2] d0 }

  condition:
    any of them
}