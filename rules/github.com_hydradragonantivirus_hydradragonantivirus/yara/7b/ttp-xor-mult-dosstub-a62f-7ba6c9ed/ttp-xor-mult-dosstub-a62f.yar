rule TTP_XOR_MULT_DOSStub_a62f {
  strings:
    $key_a62f = { f2 47 [2] 86 5f [2] c1 5d [2] 86 4c [2] c8 40 [2] c4 4a [2] d3 41 [2] c8 0f [2] f5 }

  condition:
    any of them
}