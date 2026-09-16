rule TTP_XOR_MULT_DOSStub_85f0 {
  strings:
    $key_85f0 = { d1 98 [2] a5 80 [2] e2 82 [2] a5 93 [2] eb 9f [2] e7 95 [2] f0 9e [2] eb d0 [2] d6 }

  condition:
    any of them
}