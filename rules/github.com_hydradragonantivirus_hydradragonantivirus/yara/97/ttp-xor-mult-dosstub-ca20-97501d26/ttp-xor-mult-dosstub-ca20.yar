rule TTP_XOR_MULT_DOSStub_ca20 {
  strings:
    $key_ca20 = { 9e 48 [2] ea 50 [2] ad 52 [2] ea 43 [2] a4 4f [2] a8 45 [2] bf 4e [2] a4 00 [2] 99 }

  condition:
    any of them
}