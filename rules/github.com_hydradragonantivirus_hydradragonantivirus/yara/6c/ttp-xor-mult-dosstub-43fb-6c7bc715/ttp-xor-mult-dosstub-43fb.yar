rule TTP_XOR_MULT_DOSStub_43fb {
  strings:
    $key_43fb = { 17 93 [2] 63 8b [2] 24 89 [2] 63 98 [2] 2d 94 [2] 21 9e [2] 36 95 [2] 2d db [2] 10 }

  condition:
    any of them
}