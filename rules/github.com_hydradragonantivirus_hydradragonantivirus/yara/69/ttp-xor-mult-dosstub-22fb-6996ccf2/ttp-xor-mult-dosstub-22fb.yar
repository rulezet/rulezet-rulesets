rule TTP_XOR_MULT_DOSStub_22fb {
  strings:
    $key_22fb = { 76 93 [2] 02 8b [2] 45 89 [2] 02 98 [2] 4c 94 [2] 40 9e [2] 57 95 [2] 4c db [2] 71 }

  condition:
    any of them
}