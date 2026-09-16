rule TTP_XOR_MULT_DOSStub_a67f {
  strings:
    $key_a67f = { f2 17 [2] 86 0f [2] c1 0d [2] 86 1c [2] c8 10 [2] c4 1a [2] d3 11 [2] c8 5f [2] f5 }

  condition:
    any of them
}