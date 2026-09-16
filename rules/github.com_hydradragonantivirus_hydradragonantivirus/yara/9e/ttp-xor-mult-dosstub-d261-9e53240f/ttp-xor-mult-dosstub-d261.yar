rule TTP_XOR_MULT_DOSStub_d261 {
  strings:
    $key_d261 = { 86 09 [2] f2 11 [2] b5 13 [2] f2 02 [2] bc 0e [2] b0 04 [2] a7 0f [2] bc 41 [2] 81 }

  condition:
    any of them
}