rule TTP_XOR_MULT_DOSStub_00cc {
  strings:
    $key_00cc = { 54 a4 [2] 20 bc [2] 67 be [2] 20 af [2] 6e a3 [2] 62 a9 [2] 75 a2 [2] 6e ec [2] 53 }

  condition:
    any of them
}