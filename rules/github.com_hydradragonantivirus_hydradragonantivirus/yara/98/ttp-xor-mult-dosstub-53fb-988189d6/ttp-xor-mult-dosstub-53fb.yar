rule TTP_XOR_MULT_DOSStub_53fb {
  strings:
    $key_53fb = { 07 93 [2] 73 8b [2] 34 89 [2] 73 98 [2] 3d 94 [2] 31 9e [2] 26 95 [2] 3d db [2] 00 }

  condition:
    any of them
}