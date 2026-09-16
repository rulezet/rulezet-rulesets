rule TTP_XOR_MULT_DOSStub_d6fb {
  strings:
    $key_d6fb = { 82 93 [2] f6 8b [2] b1 89 [2] f6 98 [2] b8 94 [2] b4 9e [2] a3 95 [2] b8 db [2] 85 }

  condition:
    any of them
}