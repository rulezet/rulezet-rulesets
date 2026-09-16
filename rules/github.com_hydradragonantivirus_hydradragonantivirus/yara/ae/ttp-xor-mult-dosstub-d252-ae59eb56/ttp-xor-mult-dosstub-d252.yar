rule TTP_XOR_MULT_DOSStub_d252 {
  strings:
    $key_d252 = { 86 3a [2] f2 22 [2] b5 20 [2] f2 31 [2] bc 3d [2] b0 37 [2] a7 3c [2] bc 72 [2] 81 }

  condition:
    any of them
}