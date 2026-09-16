rule TTP_XOR_MULT_DOSStub_f7fb {
  strings:
    $key_f7fb = { a3 93 [2] d7 8b [2] 90 89 [2] d7 98 [2] 99 94 [2] 95 9e [2] 82 95 [2] 99 db [2] a4 }

  condition:
    any of them
}