rule TTP_XOR_MULT_DOSStub_d2d9 {
  strings:
    $key_d2d9 = { 86 b1 [2] f2 a9 [2] b5 ab [2] f2 ba [2] bc b6 [2] b0 bc [2] a7 b7 [2] bc f9 [2] 81 }

  condition:
    any of them
}