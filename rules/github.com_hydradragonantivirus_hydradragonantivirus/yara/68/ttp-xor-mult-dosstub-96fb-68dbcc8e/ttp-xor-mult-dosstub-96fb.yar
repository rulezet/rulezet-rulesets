rule TTP_XOR_MULT_DOSStub_96fb {
  strings:
    $key_96fb = { c2 93 [2] b6 8b [2] f1 89 [2] b6 98 [2] f8 94 [2] f4 9e [2] e3 95 [2] f8 db [2] c5 }

  condition:
    any of them
}