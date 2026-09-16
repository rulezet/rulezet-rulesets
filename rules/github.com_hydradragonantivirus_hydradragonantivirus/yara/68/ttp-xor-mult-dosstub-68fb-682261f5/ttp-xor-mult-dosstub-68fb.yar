rule TTP_XOR_MULT_DOSStub_68fb {
  strings:
    $key_68fb = { 3c 93 [2] 48 8b [2] 0f 89 [2] 48 98 [2] 06 94 [2] 0a 9e [2] 1d 95 [2] 06 db [2] 3b }

  condition:
    any of them
}