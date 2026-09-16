rule TTP_XOR_MULT_DOSStub_d284 {
  strings:
    $key_d284 = { 86 ec [2] f2 f4 [2] b5 f6 [2] f2 e7 [2] bc eb [2] b0 e1 [2] a7 ea [2] bc a4 [2] 81 }

  condition:
    any of them
}