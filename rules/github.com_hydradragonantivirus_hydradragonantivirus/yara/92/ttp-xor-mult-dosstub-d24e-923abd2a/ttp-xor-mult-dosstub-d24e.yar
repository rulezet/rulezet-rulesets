rule TTP_XOR_MULT_DOSStub_d24e {
  strings:
    $key_d24e = { 86 26 [2] f2 3e [2] b5 3c [2] f2 2d [2] bc 21 [2] b0 2b [2] a7 20 [2] bc 6e [2] 81 }

  condition:
    any of them
}