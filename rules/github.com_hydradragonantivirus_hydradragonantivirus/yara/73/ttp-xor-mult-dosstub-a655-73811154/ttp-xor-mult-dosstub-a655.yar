rule TTP_XOR_MULT_DOSStub_a655 {
  strings:
    $key_a655 = { f2 3d [2] 86 25 [2] c1 27 [2] 86 36 [2] c8 3a [2] c4 30 [2] d3 3b [2] c8 75 [2] f5 }

  condition:
    any of them
}