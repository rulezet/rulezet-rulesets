rule TTP_XOR_MULT_DOSStub_d519 {
  strings:
    $key_d519 = { 81 71 [2] f5 69 [2] b2 6b [2] f5 7a [2] bb 76 [2] b7 7c [2] a0 77 [2] bb 39 [2] 86 }

  condition:
    any of them
}