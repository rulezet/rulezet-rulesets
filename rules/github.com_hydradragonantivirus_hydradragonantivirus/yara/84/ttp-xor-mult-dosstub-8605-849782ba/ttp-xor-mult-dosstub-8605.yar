rule TTP_XOR_MULT_DOSStub_8605 {
  strings:
    $key_8605 = { d2 6d [2] a6 75 [2] e1 77 [2] a6 66 [2] e8 6a [2] e4 60 [2] f3 6b [2] e8 25 [2] d5 }

  condition:
    any of them
}