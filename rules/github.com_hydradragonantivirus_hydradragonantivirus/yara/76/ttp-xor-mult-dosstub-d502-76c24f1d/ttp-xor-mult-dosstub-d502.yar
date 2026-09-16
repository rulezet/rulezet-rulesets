rule TTP_XOR_MULT_DOSStub_d502 {
  strings:
    $key_d502 = { 81 6a [2] f5 72 [2] b2 70 [2] f5 61 [2] bb 6d [2] b7 67 [2] a0 6c [2] bb 22 [2] 86 }

  condition:
    any of them
}