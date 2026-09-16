rule TTP_XOR_MULT_DOSStub_e3fb {
  strings:
    $key_e3fb = { b7 93 [2] c3 8b [2] 84 89 [2] c3 98 [2] 8d 94 [2] 81 9e [2] 96 95 [2] 8d db [2] b0 }

  condition:
    any of them
}