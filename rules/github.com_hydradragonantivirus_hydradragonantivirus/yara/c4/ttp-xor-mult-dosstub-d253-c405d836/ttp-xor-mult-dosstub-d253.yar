rule TTP_XOR_MULT_DOSStub_d253 {
  strings:
    $key_d253 = { 86 3b [2] f2 23 [2] b5 21 [2] f2 30 [2] bc 3c [2] b0 36 [2] a7 3d [2] bc 73 [2] 81 }

  condition:
    any of them
}