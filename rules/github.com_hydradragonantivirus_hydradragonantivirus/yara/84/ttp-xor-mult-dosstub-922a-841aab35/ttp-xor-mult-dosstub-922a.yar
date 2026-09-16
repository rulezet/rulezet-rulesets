rule TTP_XOR_MULT_DOSStub_922a {
  strings:
    $key_922a = { c6 42 [2] b2 5a [2] f5 58 [2] b2 49 [2] fc 45 [2] f0 4f [2] e7 44 [2] fc 0a [2] c1 }

  condition:
    any of them
}