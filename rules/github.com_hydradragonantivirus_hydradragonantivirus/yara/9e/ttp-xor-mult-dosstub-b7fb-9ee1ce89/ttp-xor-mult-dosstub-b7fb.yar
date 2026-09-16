rule TTP_XOR_MULT_DOSStub_b7fb {
  strings:
    $key_b7fb = { e3 93 [2] 97 8b [2] d0 89 [2] 97 98 [2] d9 94 [2] d5 9e [2] c2 95 [2] d9 db [2] e4 }

  condition:
    any of them
}