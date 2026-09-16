rule TTP_XOR_MULT_DOSStub_a443 {
  strings:
    $key_a443 = { f0 2b [2] 84 33 [2] c3 31 [2] 84 20 [2] ca 2c [2] c6 26 [2] d1 2d [2] ca 63 [2] f7 }

  condition:
    any of them
}