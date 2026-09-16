rule TTP_XOR_MULT_DOSStub_927a {
  strings:
    $key_927a = { c6 12 [2] b2 0a [2] f5 08 [2] b2 19 [2] fc 15 [2] f0 1f [2] e7 14 [2] fc 5a [2] c1 }

  condition:
    any of them
}