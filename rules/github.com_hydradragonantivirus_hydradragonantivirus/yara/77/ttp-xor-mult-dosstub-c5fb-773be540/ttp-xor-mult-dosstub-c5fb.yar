rule TTP_XOR_MULT_DOSStub_c5fb {
  strings:
    $key_c5fb = { 91 93 [2] e5 8b [2] a2 89 [2] e5 98 [2] ab 94 [2] a7 9e [2] b0 95 [2] ab db [2] 96 }

  condition:
    any of them
}