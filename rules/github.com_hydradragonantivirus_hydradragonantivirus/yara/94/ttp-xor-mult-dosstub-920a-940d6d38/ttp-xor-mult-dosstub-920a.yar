rule TTP_XOR_MULT_DOSStub_920a {
  strings:
    $key_920a = { c6 62 [2] b2 7a [2] f5 78 [2] b2 69 [2] fc 65 [2] f0 6f [2] e7 64 [2] fc 2a [2] c1 }

  condition:
    any of them
}