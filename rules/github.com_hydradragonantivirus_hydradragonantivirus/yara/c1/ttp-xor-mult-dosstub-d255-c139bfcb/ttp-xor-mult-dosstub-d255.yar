rule TTP_XOR_MULT_DOSStub_d255 {
  strings:
    $key_d255 = { 86 3d [2] f2 25 [2] b5 27 [2] f2 36 [2] bc 3a [2] b0 30 [2] a7 3b [2] bc 75 [2] 81 }

  condition:
    any of them
}