rule TTP_XOR_MULT_DOSStub_68cc {
  strings:
    $key_68cc = { 3c a4 [2] 48 bc [2] 0f be [2] 48 af [2] 06 a3 [2] 0a a9 [2] 1d a2 [2] 06 ec [2] 3b }

  condition:
    any of them
}