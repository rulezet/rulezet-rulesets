rule TTP_XOR_MULT_DOSStub_84fb {
  strings:
    $key_84fb = { d0 93 [2] a4 8b [2] e3 89 [2] a4 98 [2] ea 94 [2] e6 9e [2] f1 95 [2] ea db [2] d7 }

  condition:
    any of them
}