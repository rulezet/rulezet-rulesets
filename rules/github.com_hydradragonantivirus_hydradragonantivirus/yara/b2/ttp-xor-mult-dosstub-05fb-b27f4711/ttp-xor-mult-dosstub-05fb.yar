rule TTP_XOR_MULT_DOSStub_05fb {
  strings:
    $key_05fb = { 51 93 [2] 25 8b [2] 62 89 [2] 25 98 [2] 6b 94 [2] 67 9e [2] 70 95 [2] 6b db [2] 56 }

  condition:
    any of them
}