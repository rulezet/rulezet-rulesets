rule TTP_XOR_MULT_DOSStub_d575 {
  strings:
    $key_d575 = { 81 1d [2] f5 05 [2] b2 07 [2] f5 16 [2] bb 1a [2] b7 10 [2] a0 1b [2] bb 55 [2] 86 }

  condition:
    any of them
}