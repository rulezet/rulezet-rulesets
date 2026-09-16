rule TTP_XOR_MULT_DOSStub_d229 {
  strings:
    $key_d229 = { 86 41 [2] f2 59 [2] b5 5b [2] f2 4a [2] bc 46 [2] b0 4c [2] a7 47 [2] bc 09 [2] 81 }

  condition:
    any of them
}