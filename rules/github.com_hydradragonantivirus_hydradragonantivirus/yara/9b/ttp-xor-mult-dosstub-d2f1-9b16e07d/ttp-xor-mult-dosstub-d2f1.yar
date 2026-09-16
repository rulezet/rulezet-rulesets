rule TTP_XOR_MULT_DOSStub_d2f1 {
  strings:
    $key_d2f1 = { 86 99 [2] f2 81 [2] b5 83 [2] f2 92 [2] bc 9e [2] b0 94 [2] a7 9f [2] bc d1 [2] 81 }

  condition:
    any of them
}