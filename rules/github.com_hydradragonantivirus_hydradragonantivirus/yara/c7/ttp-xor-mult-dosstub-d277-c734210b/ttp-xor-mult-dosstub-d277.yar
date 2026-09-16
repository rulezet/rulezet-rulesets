rule TTP_XOR_MULT_DOSStub_d277 {
  strings:
    $key_d277 = { 86 1f [2] f2 07 [2] b5 05 [2] f2 14 [2] bc 18 [2] b0 12 [2] a7 19 [2] bc 57 [2] 81 }

  condition:
    any of them
}