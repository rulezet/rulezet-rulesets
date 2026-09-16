rule TTP_XOR_MULT_DOSStub_d20d {
  strings:
    $key_d20d = { 86 65 [2] f2 7d [2] b5 7f [2] f2 6e [2] bc 62 [2] b0 68 [2] a7 63 [2] bc 2d [2] 81 }

  condition:
    any of them
}