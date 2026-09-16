rule TTP_XOR_MULT_DOSStub_a64f {
  strings:
    $key_a64f = { f2 27 [2] 86 3f [2] c1 3d [2] 86 2c [2] c8 20 [2] c4 2a [2] d3 21 [2] c8 6f [2] f5 }

  condition:
    any of them
}