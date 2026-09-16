rule TTP_XOR_MULT_DOSStub_a64a {
  strings:
    $key_a64a = { f2 22 [2] 86 3a [2] c1 38 [2] 86 29 [2] c8 25 [2] c4 2f [2] d3 24 [2] c8 6a [2] f5 }

  condition:
    any of them
}