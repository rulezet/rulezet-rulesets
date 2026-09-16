rule TTP_XOR_MULT_DOSStub_02cc {
  strings:
    $key_02cc = { 56 a4 [2] 22 bc [2] 65 be [2] 22 af [2] 6c a3 [2] 60 a9 [2] 77 a2 [2] 6c ec [2] 51 }

  condition:
    any of them
}