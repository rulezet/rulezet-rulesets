rule TTP_XOR_MULT_DOSStub_c1fb {
  strings:
    $key_c1fb = { 95 93 [2] e1 8b [2] a6 89 [2] e1 98 [2] af 94 [2] a3 9e [2] b4 95 [2] af db [2] 92 }

  condition:
    any of them
}