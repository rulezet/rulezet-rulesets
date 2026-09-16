rule TTP_XOR_MULT_DOSStub_d210 {
  strings:
    $key_d210 = { 86 78 [2] f2 60 [2] b5 62 [2] f2 73 [2] bc 7f [2] b0 75 [2] a7 7e [2] bc 30 [2] 81 }

  condition:
    any of them
}