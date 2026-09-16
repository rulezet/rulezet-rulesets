rule TTP_XOR_MULT_DOSStub_8619 {
  strings:
    $key_8619 = { d2 71 [2] a6 69 [2] e1 6b [2] a6 7a [2] e8 76 [2] e4 7c [2] f3 77 [2] e8 39 [2] d5 }

  condition:
    any of them
}