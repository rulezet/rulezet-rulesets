rule TTP_XOR_MULT_DOSStub_c7f6 {
  strings:
    $key_c7f6 = { 93 9e [2] e7 86 [2] a0 84 [2] e7 95 [2] a9 99 [2] a5 93 [2] b2 98 [2] a9 d6 [2] 94 }

  condition:
    any of them
}