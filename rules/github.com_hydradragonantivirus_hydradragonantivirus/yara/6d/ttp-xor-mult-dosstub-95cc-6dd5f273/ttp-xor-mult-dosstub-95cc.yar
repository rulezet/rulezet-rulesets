rule TTP_XOR_MULT_DOSStub_95cc {
  strings:
    $key_95cc = { c1 a4 [2] b5 bc [2] f2 be [2] b5 af [2] fb a3 [2] f7 a9 [2] e0 a2 [2] fb ec [2] c6 }

  condition:
    any of them
}