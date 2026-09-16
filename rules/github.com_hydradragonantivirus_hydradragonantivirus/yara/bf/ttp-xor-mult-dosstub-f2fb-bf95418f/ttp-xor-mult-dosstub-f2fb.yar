rule TTP_XOR_MULT_DOSStub_f2fb {
  strings:
    $key_f2fb = { a6 93 [2] d2 8b [2] 95 89 [2] d2 98 [2] 9c 94 [2] 90 9e [2] 87 95 [2] 9c db [2] a1 }

  condition:
    any of them
}