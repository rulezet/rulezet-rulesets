rule TTP_XOR_MULT_DOSStub_a158 {
  strings:
    $key_a158 = { f5 30 [2] 81 28 [2] c6 2a [2] 81 3b [2] cf 37 [2] c3 3d [2] d4 36 [2] cf 78 [2] f2 }

  condition:
    any of them
}