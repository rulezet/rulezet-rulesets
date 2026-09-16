rule TTP_XOR_MULT_DOSStub_12fb {
  strings:
    $key_12fb = { 46 93 [2] 32 8b [2] 75 89 [2] 32 98 [2] 7c 94 [2] 70 9e [2] 67 95 [2] 7c db [2] 41 }

  condition:
    any of them
}