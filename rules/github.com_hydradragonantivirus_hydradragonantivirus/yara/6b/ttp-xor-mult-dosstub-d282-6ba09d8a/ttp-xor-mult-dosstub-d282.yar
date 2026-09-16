rule TTP_XOR_MULT_DOSStub_d282 {
  strings:
    $key_d282 = { 86 ea [2] f2 f2 [2] b5 f0 [2] f2 e1 [2] bc ed [2] b0 e7 [2] a7 ec [2] bc a2 [2] 81 }

  condition:
    any of them
}