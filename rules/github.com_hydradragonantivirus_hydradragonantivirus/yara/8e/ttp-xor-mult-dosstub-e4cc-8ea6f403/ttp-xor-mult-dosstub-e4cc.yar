rule TTP_XOR_MULT_DOSStub_e4cc {
  strings:
    $key_e4cc = { b0 a4 [2] c4 bc [2] 83 be [2] c4 af [2] 8a a3 [2] 86 a9 [2] 91 a2 [2] 8a ec [2] b7 }

  condition:
    any of them
}