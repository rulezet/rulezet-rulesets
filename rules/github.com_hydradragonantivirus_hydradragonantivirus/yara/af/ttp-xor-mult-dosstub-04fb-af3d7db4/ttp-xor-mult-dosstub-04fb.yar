rule TTP_XOR_MULT_DOSStub_04fb {
  strings:
    $key_04fb = { 50 93 [2] 24 8b [2] 63 89 [2] 24 98 [2] 6a 94 [2] 66 9e [2] 71 95 [2] 6a db [2] 57 }

  condition:
    any of them
}