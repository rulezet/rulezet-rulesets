rule TTP_XOR_MULT_DOSStub_d562 {
  strings:
    $key_d562 = { 81 0a [2] f5 12 [2] b2 10 [2] f5 01 [2] bb 0d [2] b7 07 [2] a0 0c [2] bb 42 [2] 86 }

  condition:
    any of them
}