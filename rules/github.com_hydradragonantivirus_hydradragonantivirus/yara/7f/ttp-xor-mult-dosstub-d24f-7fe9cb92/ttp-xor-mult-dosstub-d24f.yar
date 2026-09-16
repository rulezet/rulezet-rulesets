rule TTP_XOR_MULT_DOSStub_d24f {
  strings:
    $key_d24f = { 86 27 [2] f2 3f [2] b5 3d [2] f2 2c [2] bc 20 [2] b0 2a [2] a7 21 [2] bc 6f [2] 81 }

  condition:
    any of them
}