rule TTP_XOR_MULT_DOSStub_d214 {
  strings:
    $key_d214 = { 86 7c [2] f2 64 [2] b5 66 [2] f2 77 [2] bc 7b [2] b0 71 [2] a7 7a [2] bc 34 [2] 81 }

  condition:
    any of them
}