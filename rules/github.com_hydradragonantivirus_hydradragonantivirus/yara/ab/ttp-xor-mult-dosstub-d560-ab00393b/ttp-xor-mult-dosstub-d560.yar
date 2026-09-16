rule TTP_XOR_MULT_DOSStub_d560 {
  strings:
    $key_d560 = { 81 08 [2] f5 10 [2] b2 12 [2] f5 03 [2] bb 0f [2] b7 05 [2] a0 0e [2] bb 40 [2] 86 }

  condition:
    any of them
}