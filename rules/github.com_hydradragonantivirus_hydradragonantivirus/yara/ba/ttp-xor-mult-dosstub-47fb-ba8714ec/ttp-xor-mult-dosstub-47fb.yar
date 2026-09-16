rule TTP_XOR_MULT_DOSStub_47fb {
  strings:
    $key_47fb = { 13 93 [2] 67 8b [2] 20 89 [2] 67 98 [2] 29 94 [2] 25 9e [2] 32 95 [2] 29 db [2] 14 }

  condition:
    any of them
}