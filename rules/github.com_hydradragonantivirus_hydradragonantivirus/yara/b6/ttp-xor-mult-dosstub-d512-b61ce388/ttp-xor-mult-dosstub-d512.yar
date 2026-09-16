rule TTP_XOR_MULT_DOSStub_d512 {
  strings:
    $key_d512 = { 81 7a [2] f5 62 [2] b2 60 [2] f5 71 [2] bb 7d [2] b7 77 [2] a0 7c [2] bb 32 [2] 86 }

  condition:
    any of them
}