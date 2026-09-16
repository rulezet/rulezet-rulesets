rule TTP_XOR_MULT_DOSStub_52cc {
  strings:
    $key_52cc = { 06 a4 [2] 72 bc [2] 35 be [2] 72 af [2] 3c a3 [2] 30 a9 [2] 27 a2 [2] 3c ec [2] 01 }

  condition:
    any of them
}