rule TTP_XOR_MULT_DOSStub_23cc {
  strings:
    $key_23cc = { 77 a4 [2] 03 bc [2] 44 be [2] 03 af [2] 4d a3 [2] 41 a9 [2] 56 a2 [2] 4d ec [2] 70 }

  condition:
    any of them
}