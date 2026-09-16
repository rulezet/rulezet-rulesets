rule TTP_XOR_MULT_DOSStub_31cc {
  strings:
    $key_31cc = { 65 a4 [2] 11 bc [2] 56 be [2] 11 af [2] 5f a3 [2] 53 a9 [2] 44 a2 [2] 5f ec [2] 62 }

  condition:
    any of them
}