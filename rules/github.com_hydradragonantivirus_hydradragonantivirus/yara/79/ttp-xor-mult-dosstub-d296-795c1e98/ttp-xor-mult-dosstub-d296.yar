rule TTP_XOR_MULT_DOSStub_d296 {
  strings:
    $key_d296 = { 86 fe [2] f2 e6 [2] b5 e4 [2] f2 f5 [2] bc f9 [2] b0 f3 [2] a7 f8 [2] bc b6 [2] 81 }

  condition:
    any of them
}