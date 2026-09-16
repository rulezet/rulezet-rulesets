rule TTP_XOR_MULT_DOSStub_17fb {
  strings:
    $key_17fb = { 43 93 [2] 37 8b [2] 70 89 [2] 37 98 [2] 79 94 [2] 75 9e [2] 62 95 [2] 79 db [2] 44 }

  condition:
    any of them
}