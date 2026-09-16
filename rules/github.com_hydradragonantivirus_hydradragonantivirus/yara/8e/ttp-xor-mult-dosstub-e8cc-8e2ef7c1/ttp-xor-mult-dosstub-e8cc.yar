rule TTP_XOR_MULT_DOSStub_e8cc {
  strings:
    $key_e8cc = { bc a4 [2] c8 bc [2] 8f be [2] c8 af [2] 86 a3 [2] 8a a9 [2] 9d a2 [2] 86 ec [2] bb }

  condition:
    any of them
}