rule TTP_XOR_MULT_DOSStub_b082 {
  strings:
    $key_b082 = { e4 ea [2] 90 f2 [2] d7 f0 [2] 90 e1 [2] de ed [2] d2 e7 [2] c5 ec [2] de a2 [2] e3 }

  condition:
    any of them
}