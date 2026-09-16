rule TTP_XOR_MULT_DOSStub_d276 {
  strings:
    $key_d276 = { 86 1e [2] f2 06 [2] b5 04 [2] f2 15 [2] bc 19 [2] b0 13 [2] a7 18 [2] bc 56 [2] 81 }

  condition:
    any of them
}