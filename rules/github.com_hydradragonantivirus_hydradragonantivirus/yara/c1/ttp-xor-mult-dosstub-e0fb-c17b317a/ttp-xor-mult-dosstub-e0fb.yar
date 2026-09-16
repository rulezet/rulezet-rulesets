rule TTP_XOR_MULT_DOSStub_e0fb {
  strings:
    $key_e0fb = { b4 93 [2] c0 8b [2] 87 89 [2] c0 98 [2] 8e 94 [2] 82 9e [2] 95 95 [2] 8e db [2] b3 }

  condition:
    any of them
}