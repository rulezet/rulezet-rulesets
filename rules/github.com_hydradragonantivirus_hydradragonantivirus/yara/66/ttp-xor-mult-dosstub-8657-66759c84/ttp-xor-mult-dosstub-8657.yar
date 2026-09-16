rule TTP_XOR_MULT_DOSStub_8657 {
  strings:
    $key_8657 = { d2 3f [2] a6 27 [2] e1 25 [2] a6 34 [2] e8 38 [2] e4 32 [2] f3 39 [2] e8 77 [2] d5 }

  condition:
    any of them
}