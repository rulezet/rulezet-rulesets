rule TTP_XOR_MULT_DOSStub_d518 {
  strings:
    $key_d518 = { 81 70 [2] f5 68 [2] b2 6a [2] f5 7b [2] bb 77 [2] b7 7d [2] a0 76 [2] bb 38 [2] 86 }

  condition:
    any of them
}