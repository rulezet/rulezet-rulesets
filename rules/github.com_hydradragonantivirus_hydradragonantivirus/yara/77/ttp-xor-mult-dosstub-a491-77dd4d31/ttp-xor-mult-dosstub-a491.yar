rule TTP_XOR_MULT_DOSStub_a491 {
  strings:
    $key_a491 = { f0 f9 [2] 84 e1 [2] c3 e3 [2] 84 f2 [2] ca fe [2] c6 f4 [2] d1 ff [2] ca b1 [2] f7 }

  condition:
    any of them
}