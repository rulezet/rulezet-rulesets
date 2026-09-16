rule TTP_XOR_MULT_DOSStub_85e9 {
  strings:
    $key_85e9 = { d1 81 [2] a5 99 [2] e2 9b [2] a5 8a [2] eb 86 [2] e7 8c [2] f0 87 [2] eb c9 [2] d6 }

  condition:
    any of them
}