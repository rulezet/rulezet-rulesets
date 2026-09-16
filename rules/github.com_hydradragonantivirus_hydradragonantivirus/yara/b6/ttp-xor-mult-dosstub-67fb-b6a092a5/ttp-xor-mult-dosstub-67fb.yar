rule TTP_XOR_MULT_DOSStub_67fb {
  strings:
    $key_67fb = { 33 93 [2] 47 8b [2] 00 89 [2] 47 98 [2] 09 94 [2] 05 9e [2] 12 95 [2] 09 db [2] 34 }

  condition:
    any of them
}