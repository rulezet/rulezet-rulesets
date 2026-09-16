rule TTP_XOR_MULT_DOSStub_d501 {
  strings:
    $key_d501 = { 81 69 [2] f5 71 [2] b2 73 [2] f5 62 [2] bb 6e [2] b7 64 [2] a0 6f [2] bb 21 [2] 86 }

  condition:
    any of them
}