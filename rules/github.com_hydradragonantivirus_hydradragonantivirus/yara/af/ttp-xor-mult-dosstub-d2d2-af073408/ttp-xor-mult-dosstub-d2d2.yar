rule TTP_XOR_MULT_DOSStub_d2d2 {
  strings:
    $key_d2d2 = { 86 ba [2] f2 a2 [2] b5 a0 [2] f2 b1 [2] bc bd [2] b0 b7 [2] a7 bc [2] bc f2 [2] 81 }

  condition:
    any of them
}