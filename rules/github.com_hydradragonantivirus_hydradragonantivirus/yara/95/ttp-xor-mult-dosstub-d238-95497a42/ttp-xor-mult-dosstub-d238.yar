rule TTP_XOR_MULT_DOSStub_d238 {
  strings:
    $key_d238 = { 86 50 [2] f2 48 [2] b5 4a [2] f2 5b [2] bc 57 [2] b0 5d [2] a7 56 [2] bc 18 [2] 81 }

  condition:
    any of them
}