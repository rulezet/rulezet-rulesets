rule TTP_XOR_MULT_DOSStub_a042 {
  strings:
    $key_a042 = { f4 2a [2] 80 32 [2] c7 30 [2] 80 21 [2] ce 2d [2] c2 27 [2] d5 2c [2] ce 62 [2] f3 }

  condition:
    any of them
}