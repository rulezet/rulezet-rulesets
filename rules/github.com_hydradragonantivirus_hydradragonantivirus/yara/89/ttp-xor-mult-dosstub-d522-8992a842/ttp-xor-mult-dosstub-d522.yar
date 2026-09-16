rule TTP_XOR_MULT_DOSStub_d522 {
  strings:
    $key_d522 = { 81 4a [2] f5 52 [2] b2 50 [2] f5 41 [2] bb 4d [2] b7 47 [2] a0 4c [2] bb 02 [2] 86 }

  condition:
    any of them
}