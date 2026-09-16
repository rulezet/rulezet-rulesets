rule TTP_XOR_MULT_DOSStub_d21f {
  strings:
    $key_d21f = { 86 77 [2] f2 6f [2] b5 6d [2] f2 7c [2] bc 70 [2] b0 7a [2] a7 71 [2] bc 3f [2] 81 }

  condition:
    any of them
}