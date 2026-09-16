rule TTP_XOR_MULT_DOSStub_f0fb {
  strings:
    $key_f0fb = { a4 93 [2] d0 8b [2] 97 89 [2] d0 98 [2] 9e 94 [2] 92 9e [2] 85 95 [2] 9e db [2] a3 }

  condition:
    any of them
}