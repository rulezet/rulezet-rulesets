rule TTP_XOR_MULT_DOSStub_16cc {
  strings:
    $key_16cc = { 42 a4 [2] 36 bc [2] 71 be [2] 36 af [2] 78 a3 [2] 74 a9 [2] 63 a2 [2] 78 ec [2] 45 }

  condition:
    any of them
}