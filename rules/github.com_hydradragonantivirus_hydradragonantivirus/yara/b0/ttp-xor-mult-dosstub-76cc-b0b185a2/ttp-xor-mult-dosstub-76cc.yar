rule TTP_XOR_MULT_DOSStub_76cc {
  strings:
    $key_76cc = { 22 a4 [2] 56 bc [2] 11 be [2] 56 af [2] 18 a3 [2] 14 a9 [2] 03 a2 [2] 18 ec [2] 25 }

  condition:
    any of them
}