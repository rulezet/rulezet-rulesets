rule TTP_XOR_MULT_DOSStub_d265 {
  strings:
    $key_d265 = { 86 0d [2] f2 15 [2] b5 17 [2] f2 06 [2] bc 0a [2] b0 00 [2] a7 0b [2] bc 45 [2] 81 }

  condition:
    any of them
}