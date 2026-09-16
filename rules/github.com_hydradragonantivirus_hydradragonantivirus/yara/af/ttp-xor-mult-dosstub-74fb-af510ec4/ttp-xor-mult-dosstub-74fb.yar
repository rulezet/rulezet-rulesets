rule TTP_XOR_MULT_DOSStub_74fb {
  strings:
    $key_74fb = { 20 93 [2] 54 8b [2] 13 89 [2] 54 98 [2] 1a 94 [2] 16 9e [2] 01 95 [2] 1a db [2] 27 }

  condition:
    any of them
}