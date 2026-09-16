rule TTP_XOR_MULT_DOSStub_c646 {
  strings:
    $key_c646 = { 92 2e [2] e6 36 [2] a1 34 [2] e6 25 [2] a8 29 [2] a4 23 [2] b3 28 [2] a8 66 [2] 95 }

  condition:
    any of them
}