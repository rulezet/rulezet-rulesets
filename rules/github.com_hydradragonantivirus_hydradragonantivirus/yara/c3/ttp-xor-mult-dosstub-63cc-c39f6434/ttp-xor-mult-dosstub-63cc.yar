rule TTP_XOR_MULT_DOSStub_63cc {
  strings:
    $key_63cc = { 37 a4 [2] 43 bc [2] 04 be [2] 43 af [2] 0d a3 [2] 01 a9 [2] 16 a2 [2] 0d ec [2] 30 }

  condition:
    any of them
}