rule TTP_XOR_MULT_DOSStub_85ea {
  strings:
    $key_85ea = { d1 82 [2] a5 9a [2] e2 98 [2] a5 89 [2] eb 85 [2] e7 8f [2] f0 84 [2] eb ca [2] d6 }

  condition:
    any of them
}