rule TTP_XOR_MULT_DOSStub_d396 {
  strings:
    $key_d396 = { 87 fe [2] f3 e6 [2] b4 e4 [2] f3 f5 [2] bd f9 [2] b1 f3 [2] a6 f8 [2] bd b6 [2] 80 }

  condition:
    any of them
}