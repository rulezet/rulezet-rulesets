rule TTP_XOR_MULT_DOSStub_85f5 {
  strings:
    $key_85f5 = { d1 9d [2] a5 85 [2] e2 87 [2] a5 96 [2] eb 9a [2] e7 90 [2] f0 9b [2] eb d5 [2] d6 }

  condition:
    any of them
}