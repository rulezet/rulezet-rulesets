rule TTP_XOR_MULT_DOSStub_51fb {
  strings:
    $key_51fb = { 05 93 [2] 71 8b [2] 36 89 [2] 71 98 [2] 3f 94 [2] 33 9e [2] 24 95 [2] 3f db [2] 02 }

  condition:
    any of them
}