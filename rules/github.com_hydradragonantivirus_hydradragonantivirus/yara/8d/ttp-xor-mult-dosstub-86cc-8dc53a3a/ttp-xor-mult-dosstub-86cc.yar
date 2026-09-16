rule TTP_XOR_MULT_DOSStub_86cc {
  strings:
    $key_86cc = { d2 a4 [2] a6 bc [2] e1 be [2] a6 af [2] e8 a3 [2] e4 a9 [2] f3 a2 [2] e8 ec [2] d5 }

  condition:
    any of them
}