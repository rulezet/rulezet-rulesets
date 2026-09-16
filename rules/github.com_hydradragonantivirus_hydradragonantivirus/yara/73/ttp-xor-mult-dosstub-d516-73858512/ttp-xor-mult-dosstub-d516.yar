rule TTP_XOR_MULT_DOSStub_d516 {
  strings:
    $key_d516 = { 81 7e [2] f5 66 [2] b2 64 [2] f5 75 [2] bb 79 [2] b7 73 [2] a0 78 [2] bb 36 [2] 86 }

  condition:
    any of them
}