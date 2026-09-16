rule TTP_XOR_MULT_DOSStub_d527 {
  strings:
    $key_d527 = { 81 4f [2] f5 57 [2] b2 55 [2] f5 44 [2] bb 48 [2] b7 42 [2] a0 49 [2] bb 07 [2] 86 }

  condition:
    any of them
}