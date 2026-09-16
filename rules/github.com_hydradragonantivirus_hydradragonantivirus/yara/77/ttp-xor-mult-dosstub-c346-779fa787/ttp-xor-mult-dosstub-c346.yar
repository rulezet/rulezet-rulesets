rule TTP_XOR_MULT_DOSStub_c346 {
  strings:
    $key_c346 = { 97 2e [2] e3 36 [2] a4 34 [2] e3 25 [2] ad 29 [2] a1 23 [2] b6 28 [2] ad 66 [2] 90 }

  condition:
    any of them
}