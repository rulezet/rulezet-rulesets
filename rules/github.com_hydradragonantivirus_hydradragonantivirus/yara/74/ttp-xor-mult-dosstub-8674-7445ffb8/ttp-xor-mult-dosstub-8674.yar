rule TTP_XOR_MULT_DOSStub_8674 {
  strings:
    $key_8674 = { d2 1c [2] a6 04 [2] e1 06 [2] a6 17 [2] e8 1b [2] e4 11 [2] f3 1a [2] e8 54 [2] d5 }

  condition:
    any of them
}