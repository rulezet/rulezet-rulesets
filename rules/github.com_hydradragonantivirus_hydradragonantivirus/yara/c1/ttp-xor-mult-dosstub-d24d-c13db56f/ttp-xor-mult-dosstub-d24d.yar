rule TTP_XOR_MULT_DOSStub_d24d {
  strings:
    $key_d24d = { 86 25 [2] f2 3d [2] b5 3f [2] f2 2e [2] bc 22 [2] b0 28 [2] a7 23 [2] bc 6d [2] 81 }

  condition:
    any of them
}