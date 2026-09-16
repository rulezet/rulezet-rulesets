rule TTP_XOR_MULT_DOSStub_15cc {
  strings:
    $key_15cc = { 41 a4 [2] 35 bc [2] 72 be [2] 35 af [2] 7b a3 [2] 77 a9 [2] 60 a2 [2] 7b ec [2] 46 }

  condition:
    any of them
}