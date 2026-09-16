rule TTP_XOR_MULT_DOSStub_c3fb {
  strings:
    $key_c3fb = { 97 93 [2] e3 8b [2] a4 89 [2] e3 98 [2] ad 94 [2] a1 9e [2] b6 95 [2] ad db [2] 90 }

  condition:
    any of them
}