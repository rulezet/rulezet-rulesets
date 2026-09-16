rule TTP_XOR_MULT_DOSStub_b782 {
  strings:
    $key_b782 = { e3 ea [2] 97 f2 [2] d0 f0 [2] 97 e1 [2] d9 ed [2] d5 e7 [2] c2 ec [2] d9 a2 [2] e4 }

  condition:
    any of them
}