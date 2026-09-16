rule TTP_XOR_MULT_DOSStub_87fb {
  strings:
    $key_87fb = { d3 93 [2] a7 8b [2] e0 89 [2] a7 98 [2] e9 94 [2] e5 9e [2] f2 95 [2] e9 db [2] d4 }

  condition:
    any of them
}