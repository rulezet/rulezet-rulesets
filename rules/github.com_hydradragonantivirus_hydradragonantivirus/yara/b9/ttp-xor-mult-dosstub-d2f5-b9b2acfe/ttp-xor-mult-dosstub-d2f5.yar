rule TTP_XOR_MULT_DOSStub_d2f5 {
  strings:
    $key_d2f5 = { 86 9d [2] f2 85 [2] b5 87 [2] f2 96 [2] bc 9a [2] b0 90 [2] a7 9b [2] bc d5 [2] 81 }

  condition:
    any of them
}