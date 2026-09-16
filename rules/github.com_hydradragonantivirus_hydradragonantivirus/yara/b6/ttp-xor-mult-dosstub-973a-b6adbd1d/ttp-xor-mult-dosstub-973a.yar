rule TTP_XOR_MULT_DOSStub_973a {
  strings:
    $key_973a = { c3 52 [2] b7 4a [2] f0 48 [2] b7 59 [2] f9 55 [2] f5 5f [2] e2 54 [2] f9 1a [2] c4 }

  condition:
    any of them
}