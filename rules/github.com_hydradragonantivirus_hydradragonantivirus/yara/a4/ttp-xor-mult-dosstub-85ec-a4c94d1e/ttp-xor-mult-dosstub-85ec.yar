rule TTP_XOR_MULT_DOSStub_85ec {
  strings:
    $key_85ec = { d1 84 [2] a5 9c [2] e2 9e [2] a5 8f [2] eb 83 [2] e7 89 [2] f0 82 [2] eb cc [2] d6 }

  condition:
    any of them
}