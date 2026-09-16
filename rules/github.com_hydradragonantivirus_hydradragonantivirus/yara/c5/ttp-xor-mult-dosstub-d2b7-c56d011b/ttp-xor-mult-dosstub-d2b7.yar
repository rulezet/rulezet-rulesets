rule TTP_XOR_MULT_DOSStub_d2b7 {
  strings:
    $key_d2b7 = { 86 df [2] f2 c7 [2] b5 c5 [2] f2 d4 [2] bc d8 [2] b0 d2 [2] a7 d9 [2] bc 97 [2] 81 }

  condition:
    any of them
}