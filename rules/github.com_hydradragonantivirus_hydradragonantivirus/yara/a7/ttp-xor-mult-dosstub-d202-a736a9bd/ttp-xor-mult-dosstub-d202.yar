rule TTP_XOR_MULT_DOSStub_d202 {
  strings:
    $key_d202 = { 86 6a [2] f2 72 [2] b5 70 [2] f2 61 [2] bc 6d [2] b0 67 [2] a7 6c [2] bc 22 [2] 81 }

  condition:
    any of them
}