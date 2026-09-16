rule TTP_XOR_MULT_DOSStub_e3cc {
  strings:
    $key_e3cc = { b7 a4 [2] c3 bc [2] 84 be [2] c3 af [2] 8d a3 [2] 81 a9 [2] 96 a2 [2] 8d ec [2] b0 }

  condition:
    any of them
}