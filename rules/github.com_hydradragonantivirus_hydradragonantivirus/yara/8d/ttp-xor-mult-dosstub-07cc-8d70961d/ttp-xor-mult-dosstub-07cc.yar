rule TTP_XOR_MULT_DOSStub_07cc {
  strings:
    $key_07cc = { 53 a4 [2] 27 bc [2] 60 be [2] 27 af [2] 69 a3 [2] 65 a9 [2] 72 a2 [2] 69 ec [2] 54 }

  condition:
    any of them
}