rule TTP_XOR_MULT_DOSStub_d2c5 {
  strings:
    $key_d2c5 = { 86 ad [2] f2 b5 [2] b5 b7 [2] f2 a6 [2] bc aa [2] b0 a0 [2] a7 ab [2] bc e5 [2] 81 }

  condition:
    any of them
}