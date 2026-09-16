rule TTP_XOR_MULT_DOSStub_a482 {
  strings:
    $key_a482 = { f0 ea [2] 84 f2 [2] c3 f0 [2] 84 e1 [2] ca ed [2] c6 e7 [2] d1 ec [2] ca a2 [2] f7 }

  condition:
    any of them
}