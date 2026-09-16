rule TTP_XOR_MULT_DOSStub_d222 {
  strings:
    $key_d222 = { 86 4a [2] f2 52 [2] b5 50 [2] f2 41 [2] bc 4d [2] b0 47 [2] a7 4c [2] bc 02 [2] 81 }

  condition:
    any of them
}