rule TTP_XOR_MULT_DOSStub_75cc {
  strings:
    $key_75cc = { 21 a4 [2] 55 bc [2] 12 be [2] 55 af [2] 1b a3 [2] 17 a9 [2] 00 a2 [2] 1b ec [2] 26 }

  condition:
    any of them
}