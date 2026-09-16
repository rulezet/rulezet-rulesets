rule TTP_XOR_MULT_DOSStub_84f1 {
  strings:
    $key_84f1 = { d0 99 [2] a4 81 [2] e3 83 [2] a4 92 [2] ea 9e [2] e6 94 [2] f1 9f [2] ea d1 [2] d7 }

  condition:
    any of them
}