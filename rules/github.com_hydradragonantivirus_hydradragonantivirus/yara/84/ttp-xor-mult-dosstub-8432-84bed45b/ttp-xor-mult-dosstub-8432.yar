rule TTP_XOR_MULT_DOSStub_8432 {
  strings:
    $key_8432 = { d0 5a [2] a4 42 [2] e3 40 [2] a4 51 [2] ea 5d [2] e6 57 [2] f1 5c [2] ea 12 [2] d7 }

  condition:
    any of them
}