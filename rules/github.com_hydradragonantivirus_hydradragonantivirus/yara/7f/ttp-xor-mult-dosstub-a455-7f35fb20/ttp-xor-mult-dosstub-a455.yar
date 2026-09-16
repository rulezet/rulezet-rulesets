rule TTP_XOR_MULT_DOSStub_a455 {
  strings:
    $key_a455 = { f0 3d [2] 84 25 [2] c3 27 [2] 84 36 [2] ca 3a [2] c6 30 [2] d1 3b [2] ca 75 [2] f7 }

  condition:
    any of them
}