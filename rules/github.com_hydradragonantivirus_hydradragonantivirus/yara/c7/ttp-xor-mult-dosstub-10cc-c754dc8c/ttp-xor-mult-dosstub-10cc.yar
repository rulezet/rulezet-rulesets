rule TTP_XOR_MULT_DOSStub_10cc {
  strings:
    $key_10cc = { 44 a4 [2] 30 bc [2] 77 be [2] 30 af [2] 7e a3 [2] 72 a9 [2] 65 a2 [2] 7e ec [2] 43 }

  condition:
    any of them
}