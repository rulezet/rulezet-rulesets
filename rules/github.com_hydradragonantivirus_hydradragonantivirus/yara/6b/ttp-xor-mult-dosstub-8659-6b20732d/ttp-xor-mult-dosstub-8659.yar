rule TTP_XOR_MULT_DOSStub_8659 {
  strings:
    $key_8659 = { d2 31 [2] a6 29 [2] e1 2b [2] a6 3a [2] e8 36 [2] e4 3c [2] f3 37 [2] e8 79 [2] d5 }

  condition:
    any of them
}