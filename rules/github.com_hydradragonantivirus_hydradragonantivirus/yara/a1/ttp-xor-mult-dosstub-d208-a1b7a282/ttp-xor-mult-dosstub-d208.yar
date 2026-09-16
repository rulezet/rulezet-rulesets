rule TTP_XOR_MULT_DOSStub_d208 {
  strings:
    $key_d208 = { 86 60 [2] f2 78 [2] b5 7a [2] f2 6b [2] bc 67 [2] b0 6d [2] a7 66 [2] bc 28 [2] 81 }

  condition:
    any of them
}