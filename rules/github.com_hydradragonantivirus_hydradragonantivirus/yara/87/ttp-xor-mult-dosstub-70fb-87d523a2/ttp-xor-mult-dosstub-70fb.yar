rule TTP_XOR_MULT_DOSStub_70fb {
  strings:
    $key_70fb = { 24 93 [2] 50 8b [2] 17 89 [2] 50 98 [2] 1e 94 [2] 12 9e [2] 05 95 [2] 1e db [2] 23 }

  condition:
    any of them
}