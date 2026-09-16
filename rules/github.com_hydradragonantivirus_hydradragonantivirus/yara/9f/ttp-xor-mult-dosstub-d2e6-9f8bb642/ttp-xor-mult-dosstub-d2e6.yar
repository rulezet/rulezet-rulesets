rule TTP_XOR_MULT_DOSStub_d2e6 {
  strings:
    $key_d2e6 = { 86 8e [2] f2 96 [2] b5 94 [2] f2 85 [2] bc 89 [2] b0 83 [2] a7 88 [2] bc c6 [2] 81 }

  condition:
    any of them
}