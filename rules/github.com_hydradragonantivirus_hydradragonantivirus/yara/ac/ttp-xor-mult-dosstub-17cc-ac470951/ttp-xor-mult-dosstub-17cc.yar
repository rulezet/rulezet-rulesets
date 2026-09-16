rule TTP_XOR_MULT_DOSStub_17cc {
  strings:
    $key_17cc = { 43 a4 [2] 37 bc [2] 70 be [2] 37 af [2] 79 a3 [2] 75 a9 [2] 62 a2 [2] 79 ec [2] 44 }

  condition:
    any of them
}