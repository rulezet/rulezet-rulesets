rule TTP_XOR_MULT_DOSStub_52fb {
  strings:
    $key_52fb = { 06 93 [2] 72 8b [2] 35 89 [2] 72 98 [2] 3c 94 [2] 30 9e [2] 27 95 [2] 3c db [2] 01 }

  condition:
    any of them
}