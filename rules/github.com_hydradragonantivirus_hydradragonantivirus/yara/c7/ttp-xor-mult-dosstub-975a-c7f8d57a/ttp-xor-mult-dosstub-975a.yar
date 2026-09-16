rule TTP_XOR_MULT_DOSStub_975a {
  strings:
    $key_975a = { c3 32 [2] b7 2a [2] f0 28 [2] b7 39 [2] f9 35 [2] f5 3f [2] e2 34 [2] f9 7a [2] c4 }

  condition:
    any of them
}