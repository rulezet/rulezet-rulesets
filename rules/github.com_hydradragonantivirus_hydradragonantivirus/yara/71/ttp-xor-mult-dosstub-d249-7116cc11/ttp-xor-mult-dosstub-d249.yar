rule TTP_XOR_MULT_DOSStub_d249 {
  strings:
    $key_d249 = { 86 21 [2] f2 39 [2] b5 3b [2] f2 2a [2] bc 26 [2] b0 2c [2] a7 27 [2] bc 69 [2] 81 }

  condition:
    any of them
}