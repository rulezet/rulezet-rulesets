rule TTP_XOR_MULT_DOSStub_04cc {
  strings:
    $key_04cc = { 50 a4 [2] 24 bc [2] 63 be [2] 24 af [2] 6a a3 [2] 66 a9 [2] 71 a2 [2] 6a ec [2] 57 }

  condition:
    any of them
}