rule TTP_XOR_MULT_DOSStub_d573 {
  strings:
    $key_d573 = { 81 1b [2] f5 03 [2] b2 01 [2] f5 10 [2] bb 1c [2] b7 16 [2] a0 1d [2] bb 53 [2] 86 }

  condition:
    any of them
}