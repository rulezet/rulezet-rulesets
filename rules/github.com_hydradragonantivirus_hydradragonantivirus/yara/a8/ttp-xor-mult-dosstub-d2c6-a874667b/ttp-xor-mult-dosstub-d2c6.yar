rule TTP_XOR_MULT_DOSStub_d2c6 {
  strings:
    $key_d2c6 = { 86 ae [2] f2 b6 [2] b5 b4 [2] f2 a5 [2] bc a9 [2] b0 a3 [2] a7 a8 [2] bc e6 [2] 81 }

  condition:
    any of them
}