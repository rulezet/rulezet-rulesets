rule TTP_XOR_MULT_DOSStub_08cc {
  strings:
    $key_08cc = { 5c a4 [2] 28 bc [2] 6f be [2] 28 af [2] 66 a3 [2] 6a a9 [2] 7d a2 [2] 66 ec [2] 5b }

  condition:
    any of them
}