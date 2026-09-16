rule TTP_XOR_MULT_DOSStub_d245 {
  strings:
    $key_d245 = { 86 2d [2] f2 35 [2] b5 37 [2] f2 26 [2] bc 2a [2] b0 20 [2] a7 2b [2] bc 65 [2] 81 }

  condition:
    any of them
}