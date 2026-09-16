rule TTP_XOR_MULT_DOSStub_d2e4 {
  strings:
    $key_d2e4 = { 86 8c [2] f2 94 [2] b5 96 [2] f2 87 [2] bc 8b [2] b0 81 [2] a7 8a [2] bc c4 [2] 81 }

  condition:
    any of them
}