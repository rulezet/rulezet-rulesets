rule TTP_XOR_MULT_DOSStub_84f8 {
  strings:
    $key_84f8 = { d0 90 [2] a4 88 [2] e3 8a [2] a4 9b [2] ea 97 [2] e6 9d [2] f1 96 [2] ea d8 [2] d7 }

  condition:
    any of them
}