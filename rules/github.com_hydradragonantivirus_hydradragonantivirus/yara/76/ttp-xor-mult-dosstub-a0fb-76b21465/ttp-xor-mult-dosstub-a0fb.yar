rule TTP_XOR_MULT_DOSStub_a0fb {
  strings:
    $key_a0fb = { f4 93 [2] 80 8b [2] c7 89 [2] 80 98 [2] ce 94 [2] c2 9e [2] d5 95 [2] ce db [2] f3 }

  condition:
    any of them
}