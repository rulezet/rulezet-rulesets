rule TTP_XOR_MULT_DOSStub_23fb {
  strings:
    $key_23fb = { 77 93 [2] 03 8b [2] 44 89 [2] 03 98 [2] 4d 94 [2] 41 9e [2] 56 95 [2] 4d db [2] 70 }

  condition:
    any of them
}