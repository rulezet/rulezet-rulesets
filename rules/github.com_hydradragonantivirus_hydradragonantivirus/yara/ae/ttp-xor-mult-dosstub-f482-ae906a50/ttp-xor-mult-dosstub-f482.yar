rule TTP_XOR_MULT_DOSStub_f482 {
  strings:
    $key_f482 = { a0 ea [2] d4 f2 [2] 93 f0 [2] d4 e1 [2] 9a ed [2] 96 e7 [2] 81 ec [2] 9a a2 [2] a7 }

  condition:
    any of them
}