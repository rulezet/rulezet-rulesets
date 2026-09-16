rule TTP_XOR_MULT_DOSStub_a448 {
  strings:
    $key_a448 = { f0 20 [2] 84 38 [2] c3 3a [2] 84 2b [2] ca 27 [2] c6 2d [2] d1 26 [2] ca 68 [2] f7 }

  condition:
    any of them
}