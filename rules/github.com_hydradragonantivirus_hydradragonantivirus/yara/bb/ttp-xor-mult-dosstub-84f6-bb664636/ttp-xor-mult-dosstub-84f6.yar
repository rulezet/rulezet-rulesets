rule TTP_XOR_MULT_DOSStub_84f6 {
  strings:
    $key_84f6 = { d0 9e [2] a4 86 [2] e3 84 [2] a4 95 [2] ea 99 [2] e6 93 [2] f1 98 [2] ea d6 [2] d7 }

  condition:
    any of them
}