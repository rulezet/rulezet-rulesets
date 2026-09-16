rule TTP_XOR_MULT_DOSStub_03fb {
  strings:
    $key_03fb = { 57 93 [2] 23 8b [2] 64 89 [2] 23 98 [2] 6d 94 [2] 61 9e [2] 76 95 [2] 6d db [2] 50 }

  condition:
    any of them
}