rule TTP_XOR_MULT_DOSStub_d206 {
  strings:
    $key_d206 = { 86 6e [2] f2 76 [2] b5 74 [2] f2 65 [2] bc 69 [2] b0 63 [2] a7 68 [2] bc 26 [2] 81 }

  condition:
    any of them
}