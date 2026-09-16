rule TTP_XOR_MULT_DOSStub_38cc {
  strings:
    $key_38cc = { 6c a4 [2] 18 bc [2] 5f be [2] 18 af [2] 56 a3 [2] 5a a9 [2] 4d a2 [2] 56 ec [2] 6b }

  condition:
    any of them
}