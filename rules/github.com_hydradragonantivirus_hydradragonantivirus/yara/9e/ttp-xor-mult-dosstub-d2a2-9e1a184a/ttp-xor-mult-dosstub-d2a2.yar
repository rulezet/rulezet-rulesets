rule TTP_XOR_MULT_DOSStub_d2a2 {
  strings:
    $key_d2a2 = { 86 ca [2] f2 d2 [2] b5 d0 [2] f2 c1 [2] bc cd [2] b0 c7 [2] a7 cc [2] bc 82 [2] 81 }

  condition:
    any of them
}