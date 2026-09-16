rule TTP_XOR_MULT_DOSStub_95f0 {
  strings:
    $key_95f0 = { c1 98 [2] b5 80 [2] f2 82 [2] b5 93 [2] fb 9f [2] f7 95 [2] e0 9e [2] fb d0 [2] c6 }

  condition:
    any of them
}