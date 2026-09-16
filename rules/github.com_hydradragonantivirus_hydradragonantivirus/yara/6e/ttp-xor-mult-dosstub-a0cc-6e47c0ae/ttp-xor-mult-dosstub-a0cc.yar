rule TTP_XOR_MULT_DOSStub_a0cc {
  strings:
    $key_a0cc = { f4 a4 [2] 80 bc [2] c7 be [2] 80 af [2] ce a3 [2] c2 a9 [2] d5 a2 [2] ce ec [2] f3 }

  condition:
    any of them
}