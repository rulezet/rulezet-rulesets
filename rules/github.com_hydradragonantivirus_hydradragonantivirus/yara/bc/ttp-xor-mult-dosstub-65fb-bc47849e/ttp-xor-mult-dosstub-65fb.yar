rule TTP_XOR_MULT_DOSStub_65fb {
  strings:
    $key_65fb = { 31 93 [2] 45 8b [2] 02 89 [2] 45 98 [2] 0b 94 [2] 07 9e [2] 10 95 [2] 0b db [2] 36 }

  condition:
    any of them
}