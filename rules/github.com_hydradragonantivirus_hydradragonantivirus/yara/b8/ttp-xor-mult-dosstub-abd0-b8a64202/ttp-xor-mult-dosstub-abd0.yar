rule TTP_XOR_MULT_DOSStub_abd0 {
  strings:
    $key_abd0 = { ff b8 [2] 8b a0 [2] cc a2 [2] 8b b3 [2] c5 bf [2] c9 b5 [2] de be [2] c5 f0 [2] f8 }

  condition:
    any of them
}