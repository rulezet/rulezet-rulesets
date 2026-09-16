rule TTP_XOR_MULT_DOSStub_84e9 {
  strings:
    $key_84e9 = { d0 81 [2] a4 99 [2] e3 9b [2] a4 8a [2] ea 86 [2] e6 8c [2] f1 87 [2] ea c9 [2] d7 }

  condition:
    any of them
}