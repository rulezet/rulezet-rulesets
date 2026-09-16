rule TTP_XOR_MULT_DOSStub_a7cc {
  strings:
    $key_a7cc = { f3 a4 [2] 87 bc [2] c0 be [2] 87 af [2] c9 a3 [2] c5 a9 [2] d2 a2 [2] c9 ec [2] f4 }

  condition:
    any of them
}