rule TTP_XOR_MULT_DOSStub_36fb {
  strings:
    $key_36fb = { 62 93 [2] 16 8b [2] 51 89 [2] 16 98 [2] 58 94 [2] 54 9e [2] 43 95 [2] 58 db [2] 65 }

  condition:
    any of them
}