rule TTP_XOR_MULT_DOSStub_c3f6 {
  strings:
    $key_c3f6 = { 97 9e [2] e3 86 [2] a4 84 [2] e3 95 [2] ad 99 [2] a1 93 [2] b6 98 [2] ad d6 [2] 90 }

  condition:
    any of them
}