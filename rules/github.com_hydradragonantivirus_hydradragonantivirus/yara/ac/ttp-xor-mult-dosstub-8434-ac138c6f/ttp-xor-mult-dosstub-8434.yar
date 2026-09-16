rule TTP_XOR_MULT_DOSStub_8434 {
  strings:
    $key_8434 = { d0 5c [2] a4 44 [2] e3 46 [2] a4 57 [2] ea 5b [2] e6 51 [2] f1 5a [2] ea 14 [2] d7 }

  condition:
    any of them
}