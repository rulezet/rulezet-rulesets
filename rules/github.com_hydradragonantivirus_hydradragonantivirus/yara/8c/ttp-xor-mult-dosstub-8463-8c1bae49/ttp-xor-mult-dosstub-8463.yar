rule TTP_XOR_MULT_DOSStub_8463 {
  strings:
    $key_8463 = { d0 0b [2] a4 13 [2] e3 11 [2] a4 00 [2] ea 0c [2] e6 06 [2] f1 0d [2] ea 43 [2] d7 }

  condition:
    any of them
}