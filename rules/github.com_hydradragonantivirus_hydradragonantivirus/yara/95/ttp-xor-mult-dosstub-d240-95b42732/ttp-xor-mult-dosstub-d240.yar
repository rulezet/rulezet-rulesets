rule TTP_XOR_MULT_DOSStub_d240 {
  strings:
    $key_d240 = { 86 28 [2] f2 30 [2] b5 32 [2] f2 23 [2] bc 2f [2] b0 25 [2] a7 2e [2] bc 60 [2] 81 }

  condition:
    any of them
}