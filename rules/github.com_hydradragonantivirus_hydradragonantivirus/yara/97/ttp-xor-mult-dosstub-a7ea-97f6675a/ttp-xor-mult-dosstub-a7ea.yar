rule TTP_XOR_MULT_DOSStub_a7ea {
  strings:
    $key_a7ea = { f3 82 [2] 87 9a [2] c0 98 [2] 87 89 [2] c9 85 [2] c5 8f [2] d2 84 [2] c9 ca [2] f4 }

  condition:
    any of them
}