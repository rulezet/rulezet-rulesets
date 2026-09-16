rule TTP_XOR_MULT_DOSStub_05cc {
  strings:
    $key_05cc = { 51 a4 [2] 25 bc [2] 62 be [2] 25 af [2] 6b a3 [2] 67 a9 [2] 70 a2 [2] 6b ec [2] 56 }

  condition:
    any of them
}