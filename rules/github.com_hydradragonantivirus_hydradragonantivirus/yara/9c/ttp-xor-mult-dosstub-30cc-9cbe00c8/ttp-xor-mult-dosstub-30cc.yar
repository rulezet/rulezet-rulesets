rule TTP_XOR_MULT_DOSStub_30cc {
  strings:
    $key_30cc = { 64 a4 [2] 10 bc [2] 57 be [2] 10 af [2] 5e a3 [2] 52 a9 [2] 45 a2 [2] 5e ec [2] 63 }

  condition:
    any of them
}