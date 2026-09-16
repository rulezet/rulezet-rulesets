rule TTP_XOR_MULT_DOSStub_85f1 {
  strings:
    $key_85f1 = { d1 99 [2] a5 81 [2] e2 83 [2] a5 92 [2] eb 9e [2] e7 94 [2] f0 9f [2] eb d1 [2] d6 }

  condition:
    any of them
}