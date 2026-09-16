rule TTP_XOR_MULT_DOSStub_d246 {
  strings:
    $key_d246 = { 86 2e [2] f2 36 [2] b5 34 [2] f2 25 [2] bc 29 [2] b0 23 [2] a7 28 [2] bc 66 [2] 81 }

  condition:
    any of them
}