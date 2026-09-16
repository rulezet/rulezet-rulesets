rule TTP_XOR_MULT_DOSStub_d297 {
  strings:
    $key_d297 = { 86 ff [2] f2 e7 [2] b5 e5 [2] f2 f4 [2] bc f8 [2] b0 f2 [2] a7 f9 [2] bc b7 [2] 81 }

  condition:
    any of them
}