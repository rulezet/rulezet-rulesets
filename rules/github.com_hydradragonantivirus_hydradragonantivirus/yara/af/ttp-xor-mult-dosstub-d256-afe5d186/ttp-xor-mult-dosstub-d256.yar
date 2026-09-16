rule TTP_XOR_MULT_DOSStub_d256 {
  strings:
    $key_d256 = { 86 3e [2] f2 26 [2] b5 24 [2] f2 35 [2] bc 39 [2] b0 33 [2] a7 38 [2] bc 76 [2] 81 }

  condition:
    any of them
}