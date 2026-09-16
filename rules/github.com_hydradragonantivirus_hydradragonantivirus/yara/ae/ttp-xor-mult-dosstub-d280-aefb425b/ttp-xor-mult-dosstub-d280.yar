rule TTP_XOR_MULT_DOSStub_d280 {
  strings:
    $key_d280 = { 86 e8 [2] f2 f0 [2] b5 f2 [2] f2 e3 [2] bc ef [2] b0 e5 [2] a7 ee [2] bc a0 [2] 81 }

  condition:
    any of them
}