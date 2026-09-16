rule TTP_XOR_MULT_DOSStub_a6cc {
  strings:
    $key_a6cc = { f2 a4 [2] 86 bc [2] c1 be [2] 86 af [2] c8 a3 [2] c4 a9 [2] d3 a2 [2] c8 ec [2] f5 }

  condition:
    any of them
}