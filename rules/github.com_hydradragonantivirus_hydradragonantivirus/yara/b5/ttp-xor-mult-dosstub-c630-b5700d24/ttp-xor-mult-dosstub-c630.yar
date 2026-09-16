rule TTP_XOR_MULT_DOSStub_c630 {
  strings:
    $key_c630 = { 92 58 [2] e6 40 [2] a1 42 [2] e6 53 [2] a8 5f [2] a4 55 [2] b3 5e [2] a8 10 [2] 95 }

  condition:
    any of them
}