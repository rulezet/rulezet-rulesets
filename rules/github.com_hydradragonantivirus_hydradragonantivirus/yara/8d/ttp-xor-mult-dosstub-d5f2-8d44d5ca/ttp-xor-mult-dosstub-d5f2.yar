rule TTP_XOR_MULT_DOSStub_d5f2 {
  strings:
    $key_d5f2 = { 81 9a [2] f5 82 [2] b2 80 [2] f5 91 [2] bb 9d [2] b7 97 [2] a0 9c [2] bb d2 [2] 86 }

  condition:
    any of them
}