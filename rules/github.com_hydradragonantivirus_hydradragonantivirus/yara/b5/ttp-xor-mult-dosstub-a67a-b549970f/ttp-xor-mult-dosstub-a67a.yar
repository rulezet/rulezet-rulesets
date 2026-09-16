rule TTP_XOR_MULT_DOSStub_a67a {
  strings:
    $key_a67a = { f2 12 [2] 86 0a [2] c1 08 [2] 86 19 [2] c8 15 [2] c4 1f [2] d3 14 [2] c8 5a [2] f5 }

  condition:
    any of them
}