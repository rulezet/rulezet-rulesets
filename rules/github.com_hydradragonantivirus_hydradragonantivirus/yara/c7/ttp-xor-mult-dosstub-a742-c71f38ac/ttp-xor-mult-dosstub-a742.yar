rule TTP_XOR_MULT_DOSStub_a742 {
  strings:
    $key_a742 = { f3 2a [2] 87 32 [2] c0 30 [2] 87 21 [2] c9 2d [2] c5 27 [2] d2 2c [2] c9 62 [2] f4 }

  condition:
    any of them
}