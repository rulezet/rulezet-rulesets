rule TTP_XOR_MULT_DOSStub_85ee {
  strings:
    $key_85ee = { d1 86 [2] a5 9e [2] e2 9c [2] a5 8d [2] eb 81 [2] e7 8b [2] f0 80 [2] eb ce [2] d6 }

  condition:
    any of them
}