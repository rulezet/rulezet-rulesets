rule TTP_XOR_MULT_DOSStub_954a {
  strings:
    $key_954a = { c1 22 [2] b5 3a [2] f2 38 [2] b5 29 [2] fb 25 [2] f7 2f [2] e0 24 [2] fb 6a [2] c6 }

  condition:
    any of them
}