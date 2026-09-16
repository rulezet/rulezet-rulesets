rule TTP_XOR_MULT_DOSStub_36cc {
  strings:
    $key_36cc = { 62 a4 [2] 16 bc [2] 51 be [2] 16 af [2] 58 a3 [2] 54 a9 [2] 43 a2 [2] 58 ec [2] 65 }

  condition:
    any of them
}