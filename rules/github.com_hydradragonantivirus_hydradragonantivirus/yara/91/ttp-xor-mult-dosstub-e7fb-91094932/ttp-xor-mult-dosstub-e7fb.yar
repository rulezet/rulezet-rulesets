rule TTP_XOR_MULT_DOSStub_e7fb {
  strings:
    $key_e7fb = { b3 93 [2] c7 8b [2] 80 89 [2] c7 98 [2] 89 94 [2] 85 9e [2] 92 95 [2] 89 db [2] b4 }

  condition:
    any of them
}