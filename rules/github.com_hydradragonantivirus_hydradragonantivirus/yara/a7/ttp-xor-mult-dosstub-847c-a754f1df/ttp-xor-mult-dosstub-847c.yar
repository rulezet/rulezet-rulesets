rule TTP_XOR_MULT_DOSStub_847c {
  strings:
    $key_847c = { d0 14 [2] a4 0c [2] e3 0e [2] a4 1f [2] ea 13 [2] e6 19 [2] f1 12 [2] ea 5c [2] d7 }

  condition:
    any of them
}