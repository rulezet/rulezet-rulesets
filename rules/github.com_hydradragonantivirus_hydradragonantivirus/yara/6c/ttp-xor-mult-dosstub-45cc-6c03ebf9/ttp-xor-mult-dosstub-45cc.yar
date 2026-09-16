rule TTP_XOR_MULT_DOSStub_45cc {
  strings:
    $key_45cc = { 11 a4 [2] 65 bc [2] 22 be [2] 65 af [2] 2b a3 [2] 27 a9 [2] 30 a2 [2] 2b ec [2] 16 }

  condition:
    any of them
}