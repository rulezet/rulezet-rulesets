rule TTP_XOR_MULT_DOSStub_d278 {
  strings:
    $key_d278 = { 86 10 [2] f2 08 [2] b5 0a [2] f2 1b [2] bc 17 [2] b0 1d [2] a7 16 [2] bc 58 [2] 81 }

  condition:
    any of them
}