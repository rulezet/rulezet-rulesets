rule TTP_XOR_MULT_DOSStub_d2e2 {
  strings:
    $key_d2e2 = { 86 8a [2] f2 92 [2] b5 90 [2] f2 81 [2] bc 8d [2] b0 87 [2] a7 8c [2] bc c2 [2] 81 }

  condition:
    any of them
}