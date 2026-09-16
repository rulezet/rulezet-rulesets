rule TTP_XOR_MULT_DOSStub_a442 {
  strings:
    $key_a442 = { f0 2a [2] 84 32 [2] c3 30 [2] 84 21 [2] ca 2d [2] c6 27 [2] d1 2c [2] ca 62 [2] f7 }

  condition:
    any of them
}