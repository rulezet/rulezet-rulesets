rule TTP_XOR_MULT_DOSStub_90fb {
  strings:
    $key_90fb = { c4 93 [2] b0 8b [2] f7 89 [2] b0 98 [2] fe 94 [2] f2 9e [2] e5 95 [2] fe db [2] c3 }

  condition:
    any of them
}