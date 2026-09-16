rule TTP_XOR_MULT_DOSStub_957a {
  strings:
    $key_957a = { c1 12 [2] b5 0a [2] f2 08 [2] b5 19 [2] fb 15 [2] f7 1f [2] e0 14 [2] fb 5a [2] c6 }

  condition:
    any of them
}