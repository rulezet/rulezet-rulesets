rule TTP_XOR_MULT_DOSStub_d225 {
  strings:
    $key_d225 = { 86 4d [2] f2 55 [2] b5 57 [2] f2 46 [2] bc 4a [2] b0 40 [2] a7 4b [2] bc 05 [2] 81 }

  condition:
    any of them
}