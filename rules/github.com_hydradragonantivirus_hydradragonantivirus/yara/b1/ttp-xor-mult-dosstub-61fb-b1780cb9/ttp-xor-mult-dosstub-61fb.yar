rule TTP_XOR_MULT_DOSStub_61fb {
  strings:
    $key_61fb = { 35 93 [2] 41 8b [2] 06 89 [2] 41 98 [2] 0f 94 [2] 03 9e [2] 14 95 [2] 0f db [2] 32 }

  condition:
    any of them
}