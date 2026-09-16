rule TTP_XOR_MULT_DOSStub_d204 {
  strings:
    $key_d204 = { 86 6c [2] f2 74 [2] b5 76 [2] f2 67 [2] bc 6b [2] b0 61 [2] a7 6a [2] bc 24 [2] 81 }

  condition:
    any of them
}