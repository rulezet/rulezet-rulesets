rule TTP_XOR_MULT_DOSStub_d547 {
  strings:
    $key_d547 = { 81 2f [2] f5 37 [2] b2 35 [2] f5 24 [2] bb 28 [2] b7 22 [2] a0 29 [2] bb 67 [2] 86 }

  condition:
    any of them
}