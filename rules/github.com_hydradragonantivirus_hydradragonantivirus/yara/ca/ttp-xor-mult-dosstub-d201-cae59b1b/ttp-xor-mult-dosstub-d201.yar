rule TTP_XOR_MULT_DOSStub_d201 {
  strings:
    $key_d201 = { 86 69 [2] f2 71 [2] b5 73 [2] f2 62 [2] bc 6e [2] b0 64 [2] a7 6f [2] bc 21 [2] 81 }

  condition:
    any of them
}