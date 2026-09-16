rule TTP_XOR_MULT_DOSStub_d212 {
  strings:
    $key_d212 = { 86 7a [2] f2 62 [2] b5 60 [2] f2 71 [2] bc 7d [2] b0 77 [2] a7 7c [2] bc 32 [2] 81 }

  condition:
    any of them
}