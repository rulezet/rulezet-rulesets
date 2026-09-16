rule TTP_XOR_MULT_DOSStub_a6ea {
  strings:
    $key_a6ea = { f2 82 [2] 86 9a [2] c1 98 [2] 86 89 [2] c8 85 [2] c4 8f [2] d3 84 [2] c8 ca [2] f5 }

  condition:
    any of them
}