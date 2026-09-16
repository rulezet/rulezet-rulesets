rule TTP_XOR_MULT_DOSStub_8427 {
  strings:
    $key_8427 = { d0 4f [2] a4 57 [2] e3 55 [2] a4 44 [2] ea 48 [2] e6 42 [2] f1 49 [2] ea 07 [2] d7 }

  condition:
    any of them
}