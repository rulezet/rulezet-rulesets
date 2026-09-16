rule TTP_XOR_MULT_DOSStub_d207 {
  strings:
    $key_d207 = { 86 6f [2] f2 77 [2] b5 75 [2] f2 64 [2] bc 68 [2] b0 62 [2] a7 69 [2] bc 27 [2] 81 }

  condition:
    any of them
}