rule TTP_XOR_MULT_DOSStub_a63d {
  strings:
    $key_a63d = { f2 55 [2] 86 4d [2] c1 4f [2] 86 5e [2] c8 52 [2] c4 58 [2] d3 53 [2] c8 1d [2] f5 }

  condition:
    any of them
}