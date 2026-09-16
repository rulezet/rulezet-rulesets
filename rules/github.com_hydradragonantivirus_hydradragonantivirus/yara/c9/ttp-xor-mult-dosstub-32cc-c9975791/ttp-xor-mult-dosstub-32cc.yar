rule TTP_XOR_MULT_DOSStub_32cc {
  strings:
    $key_32cc = { 66 a4 [2] 12 bc [2] 55 be [2] 12 af [2] 5c a3 [2] 50 a9 [2] 47 a2 [2] 5c ec [2] 61 }

  condition:
    any of them
}