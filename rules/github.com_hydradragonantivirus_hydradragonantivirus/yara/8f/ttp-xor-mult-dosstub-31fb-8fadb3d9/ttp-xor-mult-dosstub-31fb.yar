rule TTP_XOR_MULT_DOSStub_31fb {
  strings:
    $key_31fb = { 65 93 [2] 11 8b [2] 56 89 [2] 11 98 [2] 5f 94 [2] 53 9e [2] 44 95 [2] 5f db [2] 62 }

  condition:
    any of them
}