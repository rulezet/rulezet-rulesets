rule TTP_XOR_MULT_DOSStub_847b {
  strings:
    $key_847b = { d0 13 [2] a4 0b [2] e3 09 [2] a4 18 [2] ea 14 [2] e6 1e [2] f1 15 [2] ea 5b [2] d7 }

  condition:
    any of them
}