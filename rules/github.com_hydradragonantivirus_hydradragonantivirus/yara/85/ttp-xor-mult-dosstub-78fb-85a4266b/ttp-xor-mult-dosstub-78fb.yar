rule TTP_XOR_MULT_DOSStub_78fb {
  strings:
    $key_78fb = { 2c 93 [2] 58 8b [2] 1f 89 [2] 58 98 [2] 16 94 [2] 1a 9e [2] 0d 95 [2] 16 db [2] 2b }

  condition:
    any of them
}