rule TTP_XOR_MULT_DOSStub_d2d4 {
  strings:
    $key_d2d4 = { 86 bc [2] f2 a4 [2] b5 a6 [2] f2 b7 [2] bc bb [2] b0 b1 [2] a7 ba [2] bc f4 [2] 81 }

  condition:
    any of them
}