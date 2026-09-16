rule TTP_XOR_MULT_DOSStub_a452 {
  strings:
    $key_a452 = { f0 3a [2] 84 22 [2] c3 20 [2] 84 31 [2] ca 3d [2] c6 37 [2] d1 3c [2] ca 72 [2] f7 }

  condition:
    any of them
}