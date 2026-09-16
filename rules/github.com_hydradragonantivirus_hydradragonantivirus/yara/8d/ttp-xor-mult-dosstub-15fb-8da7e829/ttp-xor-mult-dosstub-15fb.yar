rule TTP_XOR_MULT_DOSStub_15fb {
  strings:
    $key_15fb = { 41 93 [2] 35 8b [2] 72 89 [2] 35 98 [2] 7b 94 [2] 77 9e [2] 60 95 [2] 7b db [2] 46 }

  condition:
    any of them
}