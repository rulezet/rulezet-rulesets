rule TTP_XOR_MULT_DOSStub_964a {
  strings:
    $key_964a = { c2 22 [2] b6 3a [2] f1 38 [2] b6 29 [2] f8 25 [2] f4 2f [2] e3 24 [2] f8 6a [2] c5 }

  condition:
    any of them
}