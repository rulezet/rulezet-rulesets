rule TTP_XOR_MULT_DOSStub_d553 {
  strings:
    $key_d553 = { 81 3b [2] f5 23 [2] b2 21 [2] f5 30 [2] bb 3c [2] b7 36 [2] a0 3d [2] bb 73 [2] 86 }

  condition:
    any of them
}