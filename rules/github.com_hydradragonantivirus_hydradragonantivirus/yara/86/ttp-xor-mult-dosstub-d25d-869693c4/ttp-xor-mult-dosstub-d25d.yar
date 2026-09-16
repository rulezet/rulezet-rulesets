rule TTP_XOR_MULT_DOSStub_d25d {
  strings:
    $key_d25d = { 86 35 [2] f2 2d [2] b5 2f [2] f2 3e [2] bc 32 [2] b0 38 [2] a7 33 [2] bc 7d [2] 81 }

  condition:
    any of them
}