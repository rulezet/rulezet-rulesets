rule TTP_XOR_MULT_DOSStub_d27d {
  strings:
    $key_d27d = { 86 15 [2] f2 0d [2] b5 0f [2] f2 1e [2] bc 12 [2] b0 18 [2] a7 13 [2] bc 5d [2] 81 }

  condition:
    any of them
}