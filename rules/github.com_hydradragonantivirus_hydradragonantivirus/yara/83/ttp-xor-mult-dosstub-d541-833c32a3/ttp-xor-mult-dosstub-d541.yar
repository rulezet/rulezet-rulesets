rule TTP_XOR_MULT_DOSStub_d541 {
  strings:
    $key_d541 = { 81 29 [2] f5 31 [2] b2 33 [2] f5 22 [2] bb 2e [2] b7 24 [2] a0 2f [2] bb 61 [2] 86 }

  condition:
    any of them
}