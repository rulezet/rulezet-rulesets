rule TTP_XOR_MULT_DOSStub_d269 {
  strings:
    $key_d269 = { 86 01 [2] f2 19 [2] b5 1b [2] f2 0a [2] bc 06 [2] b0 0c [2] a7 07 [2] bc 49 [2] 81 }

  condition:
    any of them
}