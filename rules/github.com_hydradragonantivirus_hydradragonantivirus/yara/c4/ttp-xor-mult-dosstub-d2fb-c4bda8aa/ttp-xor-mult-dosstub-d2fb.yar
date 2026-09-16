rule TTP_XOR_MULT_DOSStub_d2fb {
  strings:
    $key_d2fb = { 86 93 [2] f2 8b [2] b5 89 [2] f2 98 [2] bc 94 [2] b0 9e [2] a7 95 [2] bc db [2] 81 }

  condition:
    any of them
}