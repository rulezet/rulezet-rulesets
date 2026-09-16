rule TTP_XOR_MULT_DOSStub_e7cc {
  strings:
    $key_e7cc = { b3 a4 [2] c7 bc [2] 80 be [2] c7 af [2] 89 a3 [2] 85 a9 [2] 92 a2 [2] 89 ec [2] b4 }

  condition:
    any of them
}