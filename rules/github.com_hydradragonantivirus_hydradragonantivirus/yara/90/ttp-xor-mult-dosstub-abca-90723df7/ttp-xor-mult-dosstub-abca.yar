rule TTP_XOR_MULT_DOSStub_abca {
  strings:
    $key_abca = { ff a2 [2] 8b ba [2] cc b8 [2] 8b a9 [2] c5 a5 [2] c9 af [2] de a4 [2] c5 ea [2] f8 }

  condition:
    any of them
}