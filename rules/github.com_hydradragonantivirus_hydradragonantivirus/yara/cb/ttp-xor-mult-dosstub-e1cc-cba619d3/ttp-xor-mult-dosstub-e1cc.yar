rule TTP_XOR_MULT_DOSStub_e1cc {
  strings:
    $key_e1cc = { b5 a4 [2] c1 bc [2] 86 be [2] c1 af [2] 8f a3 [2] 83 a9 [2] 94 a2 [2] 8f ec [2] b2 }

  condition:
    any of them
}