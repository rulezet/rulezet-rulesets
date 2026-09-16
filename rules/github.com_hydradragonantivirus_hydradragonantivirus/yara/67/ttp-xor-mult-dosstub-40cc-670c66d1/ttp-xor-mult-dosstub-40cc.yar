rule TTP_XOR_MULT_DOSStub_40cc {
  strings:
    $key_40cc = { 14 a4 [2] 60 bc [2] 27 be [2] 60 af [2] 2e a3 [2] 22 a9 [2] 35 a2 [2] 2e ec [2] 13 }

  condition:
    any of them
}