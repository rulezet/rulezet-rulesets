rule TTP_XOR_MULT_DOSStub_d5e5 {
  strings:
    $key_d5e5 = { 81 8d [2] f5 95 [2] b2 97 [2] f5 86 [2] bb 8a [2] b7 80 [2] a0 8b [2] bb c5 [2] 86 }

  condition:
    any of them
}