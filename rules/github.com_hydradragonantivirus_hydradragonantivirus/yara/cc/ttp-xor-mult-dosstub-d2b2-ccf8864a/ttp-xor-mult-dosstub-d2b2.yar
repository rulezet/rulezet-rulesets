rule TTP_XOR_MULT_DOSStub_d2b2 {
  strings:
    $key_d2b2 = { 86 da [2] f2 c2 [2] b5 c0 [2] f2 d1 [2] bc dd [2] b0 d7 [2] a7 dc [2] bc 92 [2] 81 }

  condition:
    any of them
}