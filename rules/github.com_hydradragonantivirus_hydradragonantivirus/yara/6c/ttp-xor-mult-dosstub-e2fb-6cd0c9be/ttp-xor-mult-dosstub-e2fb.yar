rule TTP_XOR_MULT_DOSStub_e2fb {
  strings:
    $key_e2fb = { b6 93 [2] c2 8b [2] 85 89 [2] c2 98 [2] 8c 94 [2] 80 9e [2] 97 95 [2] 8c db [2] b1 }

  condition:
    any of them
}