rule TTP_XOR_MULT_DOSStub_d2e1 {
  strings:
    $key_d2e1 = { 86 89 [2] f2 91 [2] b5 93 [2] f2 82 [2] bc 8e [2] b0 84 [2] a7 8f [2] bc c1 [2] 81 }

  condition:
    any of them
}