rule TTP_XOR_MULT_DOSStub_d26f {
  strings:
    $key_d26f = { 86 07 [2] f2 1f [2] b5 1d [2] f2 0c [2] bc 00 [2] b0 0a [2] a7 01 [2] bc 4f [2] 81 }

  condition:
    any of them
}