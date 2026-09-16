rule TTP_XOR_MULT_DOSStub_d7fb {
  strings:
    $key_d7fb = { 83 93 [2] f7 8b [2] b0 89 [2] f7 98 [2] b9 94 [2] b5 9e [2] a2 95 [2] b9 db [2] 84 }

  condition:
    any of them
}