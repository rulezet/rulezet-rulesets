rule TTP_XOR_MULT_DOSStub_955a {
  strings:
    $key_955a = { c1 32 [2] b5 2a [2] f2 28 [2] b5 39 [2] fb 35 [2] f7 3f [2] e0 34 [2] fb 7a [2] c6 }

  condition:
    any of them
}