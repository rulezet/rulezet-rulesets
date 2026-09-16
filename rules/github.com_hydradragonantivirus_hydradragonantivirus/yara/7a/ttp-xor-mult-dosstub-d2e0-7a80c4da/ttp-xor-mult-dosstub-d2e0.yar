rule TTP_XOR_MULT_DOSStub_d2e0 {
  strings:
    $key_d2e0 = { 86 88 [2] f2 90 [2] b5 92 [2] f2 83 [2] bc 8f [2] b0 85 [2] a7 8e [2] bc c0 [2] 81 }

  condition:
    any of them
}