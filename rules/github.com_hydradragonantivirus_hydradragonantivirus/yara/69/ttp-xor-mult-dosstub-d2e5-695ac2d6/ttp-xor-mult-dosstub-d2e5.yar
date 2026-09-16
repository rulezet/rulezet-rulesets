rule TTP_XOR_MULT_DOSStub_d2e5 {
  strings:
    $key_d2e5 = { 86 8d [2] f2 95 [2] b5 97 [2] f2 86 [2] bc 8a [2] b0 80 [2] a7 8b [2] bc c5 [2] 81 }

  condition:
    any of them
}