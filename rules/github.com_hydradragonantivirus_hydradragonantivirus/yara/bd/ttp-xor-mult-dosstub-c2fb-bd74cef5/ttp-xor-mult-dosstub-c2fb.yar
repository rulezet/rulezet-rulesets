rule TTP_XOR_MULT_DOSStub_c2fb {
  strings:
    $key_c2fb = { 96 93 [2] e2 8b [2] a5 89 [2] e2 98 [2] ac 94 [2] a0 9e [2] b7 95 [2] ac db [2] 91 }

  condition:
    any of them
}