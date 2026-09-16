rule TTP_XOR_MULT_DOSStub_a60d {
  strings:
    $key_a60d = { f2 65 [2] 86 7d [2] c1 7f [2] 86 6e [2] c8 62 [2] c4 68 [2] d3 63 [2] c8 2d [2] f5 }

  condition:
    any of them
}