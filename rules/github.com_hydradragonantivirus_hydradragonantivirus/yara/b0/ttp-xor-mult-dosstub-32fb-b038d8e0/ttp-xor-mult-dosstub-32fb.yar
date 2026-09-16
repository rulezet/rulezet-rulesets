rule TTP_XOR_MULT_DOSStub_32fb {
  strings:
    $key_32fb = { 66 93 [2] 12 8b [2] 55 89 [2] 12 98 [2] 5c 94 [2] 50 9e [2] 47 95 [2] 5c db [2] 61 }

  condition:
    any of them
}