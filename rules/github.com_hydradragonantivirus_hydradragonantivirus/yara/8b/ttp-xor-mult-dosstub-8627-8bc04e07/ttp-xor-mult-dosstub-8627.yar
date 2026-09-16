rule TTP_XOR_MULT_DOSStub_8627 {
  strings:
    $key_8627 = { d2 4f [2] a6 57 [2] e1 55 [2] a6 44 [2] e8 48 [2] e4 42 [2] f3 49 [2] e8 07 [2] d5 }

  condition:
    any of them
}