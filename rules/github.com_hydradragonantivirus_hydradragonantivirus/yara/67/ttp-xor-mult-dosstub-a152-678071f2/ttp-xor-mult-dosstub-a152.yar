rule TTP_XOR_MULT_DOSStub_a152 {
  strings:
    $key_a152 = { f5 3a [2] 81 22 [2] c6 20 [2] 81 31 [2] cf 3d [2] c3 37 [2] d4 3c [2] cf 72 [2] f2 }

  condition:
    any of them
}