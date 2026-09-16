rule TTP_XOR_MULT_DOSStub_854a {
  strings:
    $key_854a = { d1 22 [2] a5 3a [2] e2 38 [2] a5 29 [2] eb 25 [2] e7 2f [2] f0 24 [2] eb 6a [2] d6 }

  condition:
    any of them
}