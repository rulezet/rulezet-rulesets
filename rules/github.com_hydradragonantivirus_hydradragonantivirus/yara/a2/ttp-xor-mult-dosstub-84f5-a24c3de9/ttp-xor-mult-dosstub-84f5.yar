rule TTP_XOR_MULT_DOSStub_84f5 {
  strings:
    $key_84f5 = { d0 9d [2] a4 85 [2] e3 87 [2] a4 96 [2] ea 9a [2] e6 90 [2] f1 9b [2] ea d5 [2] d7 }

  condition:
    any of them
}