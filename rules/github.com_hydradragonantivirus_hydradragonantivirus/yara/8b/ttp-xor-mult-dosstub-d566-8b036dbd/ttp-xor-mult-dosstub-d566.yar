rule TTP_XOR_MULT_DOSStub_d566 {
  strings:
    $key_d566 = { 81 0e [2] f5 16 [2] b2 14 [2] f5 05 [2] bb 09 [2] b7 03 [2] a0 08 [2] bb 46 [2] 86 }

  condition:
    any of them
}