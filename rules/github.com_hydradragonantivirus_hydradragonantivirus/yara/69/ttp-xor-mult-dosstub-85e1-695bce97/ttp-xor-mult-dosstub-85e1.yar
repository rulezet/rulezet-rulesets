rule TTP_XOR_MULT_DOSStub_85e1 {
  strings:
    $key_85e1 = { d1 89 [2] a5 91 [2] e2 93 [2] a5 82 [2] eb 8e [2] e7 84 [2] f0 8f [2] eb c1 [2] d6 }

  condition:
    any of them
}