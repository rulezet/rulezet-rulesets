rule TTP_XOR_MULT_DOSStub_84e4 {
  strings:
    $key_84e4 = { d0 8c [2] a4 94 [2] e3 96 [2] a4 87 [2] ea 8b [2] e6 81 [2] f1 8a [2] ea c4 [2] d7 }

  condition:
    any of them
}