rule TTP_XOR_MULT_DOSStub_d21d {
  strings:
    $key_d21d = { 86 75 [2] f2 6d [2] b5 6f [2] f2 7e [2] bc 72 [2] b0 78 [2] a7 73 [2] bc 3d [2] 81 }

  condition:
    any of them
}