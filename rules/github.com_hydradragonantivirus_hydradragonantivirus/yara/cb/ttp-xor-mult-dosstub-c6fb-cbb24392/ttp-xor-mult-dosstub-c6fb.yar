rule TTP_XOR_MULT_DOSStub_c6fb {
  strings:
    $key_c6fb = { 92 93 [2] e6 8b [2] a1 89 [2] e6 98 [2] a8 94 [2] a4 9e [2] b3 95 [2] a8 db [2] 95 }

  condition:
    any of them
}