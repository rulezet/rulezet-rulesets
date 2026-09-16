rule TTP_XOR_MULT_DOSStub_d247 {
  strings:
    $key_d247 = { 86 2f [2] f2 37 [2] b5 35 [2] f2 24 [2] bc 28 [2] b0 22 [2] a7 29 [2] bc 67 [2] 81 }

  condition:
    any of them
}