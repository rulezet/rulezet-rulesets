rule TTP_XOR_MULT_DOSStub_a5cc {
  strings:
    $key_a5cc = { f1 a4 [2] 85 bc [2] c2 be [2] 85 af [2] cb a3 [2] c7 a9 [2] d0 a2 [2] cb ec [2] f6 }

  condition:
    any of them
}