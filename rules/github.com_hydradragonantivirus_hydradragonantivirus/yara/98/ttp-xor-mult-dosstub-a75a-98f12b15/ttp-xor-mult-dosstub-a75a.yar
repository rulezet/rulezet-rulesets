rule TTP_XOR_MULT_DOSStub_a75a {
  strings:
    $key_a75a = { f3 32 [2] 87 2a [2] c0 28 [2] 87 39 [2] c9 35 [2] c5 3f [2] d2 34 [2] c9 7a [2] f4 }

  condition:
    any of them
}