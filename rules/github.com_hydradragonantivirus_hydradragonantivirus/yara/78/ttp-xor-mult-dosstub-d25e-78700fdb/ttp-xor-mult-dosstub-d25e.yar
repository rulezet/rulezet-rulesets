rule TTP_XOR_MULT_DOSStub_d25e {
  strings:
    $key_d25e = { 86 36 [2] f2 2e [2] b5 2c [2] f2 3d [2] bc 31 [2] b0 3b [2] a7 30 [2] bc 7e [2] 81 }

  condition:
    any of them
}