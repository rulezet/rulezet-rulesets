rule TTP_XOR_MULT_DOSStub_963a {
  strings:
    $key_963a = { c2 52 [2] b6 4a [2] f1 48 [2] b6 59 [2] f8 55 [2] f4 5f [2] e3 54 [2] f8 1a [2] c5 }

  condition:
    any of them
}