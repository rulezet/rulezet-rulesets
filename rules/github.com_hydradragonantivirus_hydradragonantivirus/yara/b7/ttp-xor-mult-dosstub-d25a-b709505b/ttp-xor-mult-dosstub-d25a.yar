rule TTP_XOR_MULT_DOSStub_d25a {
  strings:
    $key_d25a = { 86 32 [2] f2 2a [2] b5 28 [2] f2 39 [2] bc 35 [2] b0 3f [2] a7 34 [2] bc 7a [2] 81 }

  condition:
    any of them
}