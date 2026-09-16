rule TTP_XOR_MULT_DOSStub_8284 {
  strings:
    $key_8284 = { d6 ec [2] a2 f4 [2] e5 f6 [2] a2 e7 [2] ec eb [2] e0 e1 [2] f7 ea [2] ec a4 [2] d1 }

  condition:
    any of them
}