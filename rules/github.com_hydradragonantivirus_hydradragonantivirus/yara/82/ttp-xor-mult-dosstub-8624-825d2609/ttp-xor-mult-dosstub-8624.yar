rule TTP_XOR_MULT_DOSStub_8624 {
  strings:
    $key_8624 = { d2 4c [2] a6 54 [2] e1 56 [2] a6 47 [2] e8 4b [2] e4 41 [2] f3 4a [2] e8 04 [2] d5 }

  condition:
    any of them
}