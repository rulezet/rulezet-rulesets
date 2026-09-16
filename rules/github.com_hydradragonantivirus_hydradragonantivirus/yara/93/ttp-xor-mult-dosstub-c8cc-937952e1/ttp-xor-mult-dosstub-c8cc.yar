rule TTP_XOR_MULT_DOSStub_c8cc {
  strings:
    $key_c8cc = { 9c a4 [2] e8 bc [2] af be [2] e8 af [2] a6 a3 [2] aa a9 [2] bd a2 [2] a6 ec [2] 9b }

  condition:
    any of them
}