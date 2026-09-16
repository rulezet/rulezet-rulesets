rule TTP_XOR_MULT_DOSStub_54fb {
  strings:
    $key_54fb = { 00 93 [2] 74 8b [2] 33 89 [2] 74 98 [2] 3a 94 [2] 36 9e [2] 21 95 [2] 3a db [2] 07 }

  condition:
    any of them
}