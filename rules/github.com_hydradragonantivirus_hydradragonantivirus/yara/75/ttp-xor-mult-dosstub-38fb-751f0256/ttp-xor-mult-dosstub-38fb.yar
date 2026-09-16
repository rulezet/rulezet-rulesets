rule TTP_XOR_MULT_DOSStub_38fb {
  strings:
    $key_38fb = { 6c 93 [2] 18 8b [2] 5f 89 [2] 18 98 [2] 56 94 [2] 5a 9e [2] 4d 95 [2] 56 db [2] 6b }

  condition:
    any of them
}