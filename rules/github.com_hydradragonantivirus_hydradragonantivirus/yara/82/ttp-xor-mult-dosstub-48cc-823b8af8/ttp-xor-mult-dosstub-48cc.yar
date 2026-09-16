rule TTP_XOR_MULT_DOSStub_48cc {
  strings:
    $key_48cc = { 1c a4 [2] 68 bc [2] 2f be [2] 68 af [2] 26 a3 [2] 2a a9 [2] 3d a2 [2] 26 ec [2] 1b }

  condition:
    any of them
}