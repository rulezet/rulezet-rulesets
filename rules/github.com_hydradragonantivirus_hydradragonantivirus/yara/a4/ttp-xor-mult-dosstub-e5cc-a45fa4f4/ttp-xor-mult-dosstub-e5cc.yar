rule TTP_XOR_MULT_DOSStub_e5cc {
  strings:
    $key_e5cc = { b1 a4 [2] c5 bc [2] 82 be [2] c5 af [2] 8b a3 [2] 87 a9 [2] 90 a2 [2] 8b ec [2] b6 }

  condition:
    any of them
}