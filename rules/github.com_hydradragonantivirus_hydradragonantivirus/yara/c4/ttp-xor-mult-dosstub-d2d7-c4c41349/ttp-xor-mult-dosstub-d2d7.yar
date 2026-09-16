rule TTP_XOR_MULT_DOSStub_d2d7 {
  strings:
    $key_d2d7 = { 86 bf [2] f2 a7 [2] b5 a5 [2] f2 b4 [2] bc b8 [2] b0 b2 [2] a7 b9 [2] bc f7 [2] 81 }

  condition:
    any of them
}