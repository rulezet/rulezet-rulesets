rule TTP_XOR_MULT_DOSStub_d2e9 {
  strings:
    $key_d2e9 = { 86 81 [2] f2 99 [2] b5 9b [2] f2 8a [2] bc 86 [2] b0 8c [2] a7 87 [2] bc c9 [2] 81 }

  condition:
    any of them
}