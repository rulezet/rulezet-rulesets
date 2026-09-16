rule TTP_XOR_MULT_DOSStub_a64d {
  strings:
    $key_a64d = { f2 25 [2] 86 3d [2] c1 3f [2] 86 2e [2] c8 22 [2] c4 28 [2] d3 23 [2] c8 6d [2] f5 }

  condition:
    any of them
}