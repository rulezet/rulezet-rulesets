rule TTP_XOR_MULT_DOSStub_20fb {
  strings:
    $key_20fb = { 74 93 [2] 00 8b [2] 47 89 [2] 00 98 [2] 4e 94 [2] 42 9e [2] 55 95 [2] 4e db [2] 73 }

  condition:
    any of them
}