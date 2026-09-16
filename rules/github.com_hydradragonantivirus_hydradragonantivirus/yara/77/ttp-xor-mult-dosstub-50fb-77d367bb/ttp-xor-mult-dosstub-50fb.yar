rule TTP_XOR_MULT_DOSStub_50fb {
  strings:
    $key_50fb = { 04 93 [2] 70 8b [2] 37 89 [2] 70 98 [2] 3e 94 [2] 32 9e [2] 25 95 [2] 3e db [2] 03 }

  condition:
    any of them
}