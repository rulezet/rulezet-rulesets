rule TTP_XOR_MULT_DOSStub_d2d6 {
  strings:
    $key_d2d6 = { 86 be [2] f2 a6 [2] b5 a4 [2] f2 b5 [2] bc b9 [2] b0 b3 [2] a7 b8 [2] bc f6 [2] 81 }

  condition:
    any of them
}