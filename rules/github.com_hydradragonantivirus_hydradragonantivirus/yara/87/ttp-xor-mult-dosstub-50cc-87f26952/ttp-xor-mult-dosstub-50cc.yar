rule TTP_XOR_MULT_DOSStub_50cc {
  strings:
    $key_50cc = { 04 a4 [2] 70 bc [2] 37 be [2] 70 af [2] 3e a3 [2] 32 a9 [2] 25 a2 [2] 3e ec [2] 03 }

  condition:
    any of them
}