rule TTP_XOR_MULT_DOSStub_e482 {
  strings:
    $key_e482 = { b0 ea [2] c4 f2 [2] 83 f0 [2] c4 e1 [2] 8a ed [2] 86 e7 [2] 91 ec [2] 8a a2 [2] b7 }

  condition:
    any of them
}