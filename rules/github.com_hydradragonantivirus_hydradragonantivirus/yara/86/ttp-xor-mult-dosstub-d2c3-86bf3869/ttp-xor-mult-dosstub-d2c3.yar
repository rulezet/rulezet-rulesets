rule TTP_XOR_MULT_DOSStub_d2c3 {
  strings:
    $key_d2c3 = { 86 ab [2] f2 b3 [2] b5 b1 [2] f2 a0 [2] bc ac [2] b0 a6 [2] a7 ad [2] bc e3 [2] 81 }

  condition:
    any of them
}