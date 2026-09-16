rule TTP_XOR_MULT_DOSStub_a182 {
  strings:
    $key_a182 = { f5 ea [2] 81 f2 [2] c6 f0 [2] 81 e1 [2] cf ed [2] c3 e7 [2] d4 ec [2] cf a2 [2] f2 }

  condition:
    any of them
}