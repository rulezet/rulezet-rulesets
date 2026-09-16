rule TTP_XOR_MULT_DOSStub_c746 {
  strings:
    $key_c746 = { 93 2e [2] e7 36 [2] a0 34 [2] e7 25 [2] a9 29 [2] a5 23 [2] b2 28 [2] a9 66 [2] 94 }

  condition:
    any of them
}