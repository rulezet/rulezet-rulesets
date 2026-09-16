rule TTP_XOR_MULT_DOSStub_85f7 {
  strings:
    $key_85f7 = { d1 9f [2] a5 87 [2] e2 85 [2] a5 94 [2] eb 98 [2] e7 92 [2] f0 99 [2] eb d7 [2] d6 }

  condition:
    any of them
}