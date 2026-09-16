rule TTP_XOR_MULT_DOSStub_977a {
  strings:
    $key_977a = { c3 12 [2] b7 0a [2] f0 08 [2] b7 19 [2] f9 15 [2] f5 1f [2] e2 14 [2] f9 5a [2] c4 }

  condition:
    any of them
}