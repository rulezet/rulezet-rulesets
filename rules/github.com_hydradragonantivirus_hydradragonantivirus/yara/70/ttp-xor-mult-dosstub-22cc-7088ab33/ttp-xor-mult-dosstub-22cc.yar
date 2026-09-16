rule TTP_XOR_MULT_DOSStub_22cc {
  strings:
    $key_22cc = { 76 a4 [2] 02 bc [2] 45 be [2] 02 af [2] 4c a3 [2] 40 a9 [2] 57 a2 [2] 4c ec [2] 71 }

  condition:
    any of them
}