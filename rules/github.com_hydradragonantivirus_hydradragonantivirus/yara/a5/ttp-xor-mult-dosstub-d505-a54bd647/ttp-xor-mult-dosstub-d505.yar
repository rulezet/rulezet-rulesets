rule TTP_XOR_MULT_DOSStub_d505 {
  strings:
    $key_d505 = { 81 6d [2] f5 75 [2] b2 77 [2] f5 66 [2] bb 6a [2] b7 60 [2] a0 6b [2] bb 25 [2] 86 }

  condition:
    any of them
}