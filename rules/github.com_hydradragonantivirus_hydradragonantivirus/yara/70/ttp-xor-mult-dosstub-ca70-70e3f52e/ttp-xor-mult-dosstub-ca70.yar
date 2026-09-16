rule TTP_XOR_MULT_DOSStub_ca70 {
  strings:
    $key_ca70 = { 9e 18 [2] ea 00 [2] ad 02 [2] ea 13 [2] a4 1f [2] a8 15 [2] bf 1e [2] a4 50 [2] 99 }

  condition:
    any of them
}