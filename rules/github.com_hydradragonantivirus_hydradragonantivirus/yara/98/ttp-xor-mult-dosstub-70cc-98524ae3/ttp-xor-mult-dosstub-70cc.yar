rule TTP_XOR_MULT_DOSStub_70cc {
  strings:
    $key_70cc = { 24 a4 [2] 50 bc [2] 17 be [2] 50 af [2] 1e a3 [2] 12 a9 [2] 05 a2 [2] 1e ec [2] 23 }

  condition:
    any of them
}