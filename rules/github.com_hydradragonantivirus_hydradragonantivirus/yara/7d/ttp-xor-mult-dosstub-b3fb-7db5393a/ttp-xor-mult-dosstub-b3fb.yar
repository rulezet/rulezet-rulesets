rule TTP_XOR_MULT_DOSStub_b3fb {
  strings:
    $key_b3fb = { e7 93 [2] 93 8b [2] d4 89 [2] 93 98 [2] dd 94 [2] d1 9e [2] c6 95 [2] dd db [2] e0 }

  condition:
    any of them
}