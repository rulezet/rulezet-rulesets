rule TTP_XOR_MULT_DOSStub_965a {
  strings:
    $key_965a = { c2 32 [2] b6 2a [2] f1 28 [2] b6 39 [2] f8 35 [2] f4 3f [2] e3 34 [2] f8 7a [2] c5 }

  condition:
    any of them
}