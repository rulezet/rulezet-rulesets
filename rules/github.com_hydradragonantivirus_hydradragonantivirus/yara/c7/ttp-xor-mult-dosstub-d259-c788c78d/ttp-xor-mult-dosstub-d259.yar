rule TTP_XOR_MULT_DOSStub_d259 {
  strings:
    $key_d259 = { 86 31 [2] f2 29 [2] b5 2b [2] f2 3a [2] bc 36 [2] b0 3c [2] a7 37 [2] bc 79 [2] 81 }

  condition:
    any of them
}