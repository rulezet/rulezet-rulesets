rule TTP_XOR_MULT_DOSStub_953a {
  strings:
    $key_953a = { c1 52 [2] b5 4a [2] f2 48 [2] b5 59 [2] fb 55 [2] f7 5f [2] e0 54 [2] fb 1a [2] c6 }

  condition:
    any of them
}