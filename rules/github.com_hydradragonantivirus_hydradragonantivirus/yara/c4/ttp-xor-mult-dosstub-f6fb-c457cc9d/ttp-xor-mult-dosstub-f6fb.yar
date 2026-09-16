rule TTP_XOR_MULT_DOSStub_f6fb {
  strings:
    $key_f6fb = { a2 93 [2] d6 8b [2] 91 89 [2] d6 98 [2] 98 94 [2] 94 9e [2] 83 95 [2] 98 db [2] a5 }

  condition:
    any of them
}