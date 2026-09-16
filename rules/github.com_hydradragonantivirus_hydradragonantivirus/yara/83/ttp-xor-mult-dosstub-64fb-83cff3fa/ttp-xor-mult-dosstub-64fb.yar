rule TTP_XOR_MULT_DOSStub_64fb {
  strings:
    $key_64fb = { 30 93 [2] 44 8b [2] 03 89 [2] 44 98 [2] 0a 94 [2] 06 9e [2] 11 95 [2] 0a db [2] 37 }

  condition:
    any of them
}