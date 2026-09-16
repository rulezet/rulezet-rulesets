rule TTP_XOR_MULT_DOSStub_a1fb {
  strings:
    $key_a1fb = { f5 93 [2] 81 8b [2] c6 89 [2] 81 98 [2] cf 94 [2] c3 9e [2] d4 95 [2] cf db [2] f2 }

  condition:
    any of them
}