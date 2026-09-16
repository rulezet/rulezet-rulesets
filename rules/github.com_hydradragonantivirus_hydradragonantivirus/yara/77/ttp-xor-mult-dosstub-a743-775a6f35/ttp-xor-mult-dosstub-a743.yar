rule TTP_XOR_MULT_DOSStub_a743 {
  strings:
    $key_a743 = { f3 2b [2] 87 33 [2] c0 31 [2] 87 20 [2] c9 2c [2] c5 26 [2] d2 2d [2] c9 63 [2] f4 }

  condition:
    any of them
}