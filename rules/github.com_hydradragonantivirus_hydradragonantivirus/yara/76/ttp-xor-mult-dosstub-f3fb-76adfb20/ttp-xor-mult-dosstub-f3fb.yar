rule TTP_XOR_MULT_DOSStub_f3fb {
  strings:
    $key_f3fb = { a7 93 [2] d3 8b [2] 94 89 [2] d3 98 [2] 9d 94 [2] 91 9e [2] 86 95 [2] 9d db [2] a0 }

  condition:
    any of them
}